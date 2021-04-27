# Copyright 2020, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""TUF client 1.0.0 draft

TODO

"""

import fnmatch
import logging
import os
from typing import Dict, Optional

from securesystemslib import exceptions as sslib_exceptions
from securesystemslib import hash as sslib_hash
from securesystemslib import util as sslib_util

from tuf import exceptions, settings
from tuf.client.fetcher import FetcherInterface
from tuf.client_rework import download, mirrors, requests_fetcher
from tuf.client_rework.metadata_bundle import MetadataBundle

# Globals
logger = logging.getLogger(__name__)

# Classes
class Updater:
    """
    Provides a class that can download target files securely.

    Attributes:
        metadata:

        repository_name:

        mirrors:

        fetcher:

        consistent_snapshot:
    """

    def __init__(
        self,
        repository_name: str,
        repository_mirrors: Dict,
        fetcher: Optional[FetcherInterface] = None,
    ):

        self._repository_name = repository_name
        self._mirrors = repository_mirrors
        self._consistent_snapshot = False
        self._metadata = {}

        if fetcher is None:
            self._fetcher = requests_fetcher.RequestsFetcher()
        else:
            self._fetcher = fetcher

        # TODO: who's responsible for ensuring the path exists?
        metadata_path = os.path.join(
            settings.repositories_directory,
            self._repository_name,
            "metadata",
            "current",
        )

        # On initialization of MetadataBundle, the last trusted root is
        # loaded from the file system.
        self._trusted_bundle = MetadataBundle(metadata_path)

    def refresh(self) -> None:
        """
        This method downloads, verifies, and loads metadata for the top-level
        roles in a specific order (root -> timestamp -> snapshot -> targets)
        The expiration time for downloaded metadata is also verified.

        The metadata for delegated roles are not refreshed by this method, but
        by the method that returns targetinfo (i.e.,
        get_one_valid_targetinfo()).

        The refresh() method should be called by the client before any target
        requests.
        """

        self._load_root()
        self._load_timestamp()
        self._load_snapshot()
        self._load_targets()

    def get_one_valid_targetinfo(self, filename: str) -> Dict:
        """
        Returns the target information for a specific file identified by its
        file path.  This target method also downloads the metadata of updated
        targets.
        """
        return self._preorder_depth_first_walk(filename)

    @staticmethod
    def updated_targets(targets: Dict, destination_directory: str) -> Dict:
        """
        After the client has retrieved the target information for those targets
        they are interested in updating, they would call this method to
        determine which targets have changed from those saved locally on disk.
        All the targets that have changed are returns in a list.  From this
        list, they can request a download by calling 'download_target()'.
        """
        # Keep track of the target objects and filepaths of updated targets.
        # Return 'updated_targets' and use 'updated_targetpaths' to avoid
        # duplicates.
        updated_targets = []
        updated_targetpaths = []

        for target in targets:
            # Prepend 'destination_directory' to the target's relative filepath
            # (as stored in metadata.)  Verify the hash of 'target_filepath'
            # against each hash listed for its fileinfo.  Note: join() discards
            # 'destination_directory' if 'filepath' contains a leading path
            # separator (i.e., is treated as an absolute path).
            filepath = target["filepath"]
            target_filepath = os.path.join(destination_directory, filepath)

            if target_filepath in updated_targetpaths:
                continue

            # Try one of the algorithm/digest combos for a mismatch.  We break
            # as soon as we find a mismatch.
            for algorithm, digest in target["fileinfo"]["hashes"].items():
                digest_object = None
                try:
                    digest_object = sslib_hash.digest_filename(
                        target_filepath, algorithm=algorithm
                    )

                # This exception will occur if the target does not exist
                # locally.
                except sslib_exceptions.StorageError:
                    updated_targets.append(target)
                    updated_targetpaths.append(target_filepath)
                    break

                # The file does exist locally, check if its hash differs.
                if digest_object.hexdigest() != digest:
                    updated_targets.append(target)
                    updated_targetpaths.append(target_filepath)
                    break

        return updated_targets

    def download_target(self, target: Dict, destination_directory: str):
        """
        This method performs the actual download of the specified target.
        The file is saved to the 'destination_directory' argument.
        """

        temp_obj = None
        file_mirrors = mirrors.get_list_of_mirrors(
            "target", target["filepath"], self._mirrors
        )

        for file_mirror in file_mirrors:
            try:
                temp_obj = download.download_file(
                    file_mirror, target["fileinfo"]["length"], self._fetcher
                )
                _check_file_length(temp_obj, target["fileinfo"]["length"])
                temp_obj.seek(0)
                _check_hashes_obj(temp_obj, target["fileinfo"]["hashes"])
                break

            except Exception as exception:
                if temp_obj:
                    temp_obj.close()
                raise exceptions.NoWorkingMirrorError({file_mirror: exception})

        filepath = os.path.join(destination_directory, target["filepath"])
        sslib_util.persist_temp_file(temp_obj, filepath)
        temp_obj.close()

    def _load_root(self) -> None:
        """
        If metadata file for 'root' role does not exist locally, download it
        over a network, verify it and store it permanently.
        """

        # Update the root role
        # 1.1. Let N denote the version number of the trusted
        # root metadata file.
        lower_bound = self._trusted_bundle.root.signed.version + 1
        upper_bound = lower_bound + settings.MAX_NUMBER_ROOT_ROTATIONS

        for next_version in range(lower_bound, upper_bound):
            try:
                root_mirrors = mirrors.get_list_of_mirrors(
                    "meta",
                    f"{next_version}.root.json",
                    self._mirrors,
                )

                # For each version of root iterate over the list of mirrors
                # until an intermediate root is successfully downloaded and
                # verified.
                self._root_mirrors_download(root_mirrors)

            # Exit the loop when all mirrors have raised only 403 / 404 errors,
            # which indicates that a bigger root version does not exist.
            except exceptions.NoWorkingMirrorError as exception:
                for mirror_error in exception.mirror_errors.values():
                    # Otherwise, reraise the error, because it is not a simple
                    # HTTP error.
                    if neither_403_nor_404(mirror_error):
                        logger.info(
                            "Misc error for root version " + str(next_version)
                        )
                        raise

                logger.debug("HTTP error for root version " + str(next_version))
                # If we are here, then we ran into only 403 / 404 errors, which
                # are good reasons to suspect that the next root metadata file
                # does not exist.
                break

        self._trusted_bundle.root_update_finished()

    def _root_mirrors_download(self, root_mirrors: Dict) -> "RootWrapper":
        """Iterate over the list of "root_mirrors" until an intermediate
        root is successfully downloaded and verified.
        Raise "NoWorkingMirrorError" if a root file cannot be downloaded or
        verified from any mirror"""

        file_mirror_errors = {}
        temp_obj = None

        for root_mirror in root_mirrors:
            try:
                temp_obj = download.download_file(
                    root_mirror,
                    settings.DEFAULT_ROOT_REQUIRED_LENGTH,
                    self._fetcher,
                    strict_required_length=False,
                )

                temp_obj.seek(0)
                self._trusted_bundle.update_metadata(temp_obj.read(), "root")
                # When we reach this point, a root file has been successfully
                # downloaded and verified so we can return.
                return

            # pylint cannot figure out that we store the exceptions
            # in a dictionary to raise them later so we disable
            # the warning. This should be reviewed in the future still.
            except Exception as exception:  # pylint:  disable=broad-except
                # Store the exceptions until all mirrors are iterated.
                # If an exception is raised from one mirror but a valid
                # file is found in the next one, the first exception is ignored.
                file_mirror_errors[root_mirror] = exception

            finally:
                if temp_obj:
                    temp_obj.close()

        # If all mirrors are tried but a valid root file is not found,
        # then raise an exception with the stored errors
        raise exceptions.NoWorkingMirrorError(file_mirror_errors)

    def _load_timestamp(self) -> None:
        """
        TODO
        """

        if not self._trusted_bundle.load_local_metadata("timestamp"):

            file_mirrors = mirrors.get_list_of_mirrors(
                "meta", "timestamp.json", self._mirrors
            )

            file_mirror_errors = {}
            for file_mirror in file_mirrors:
                try:
                    temp_obj = download.download_file(
                        file_mirror,
                        settings.DEFAULT_TIMESTAMP_REQUIRED_LENGTH,
                        self._fetcher,
                        strict_required_length=False,
                    )

                    temp_obj.seek(0)
                    self._trusted_bundle.update_metadata(
                        temp_obj.read(), "timestamp"
                    )
                    return

                except Exception as exception:  # pylint:  disable=broad-except
                    file_mirror_errors[file_mirror] = exception

                finally:
                    if temp_obj:
                        temp_obj.close()

            raise exceptions.NoWorkingMirrorError(file_mirror_errors)

    def _load_snapshot(self) -> None:
        """
        TODO
        """

        if not self._trusted_bundle.load_local_metadata("snapshot"):
            try:
                length = self._trusted_bundle.timestamp.signed.meta[
                    "snapshot.json"
                ]["length"]
            except KeyError:
                length = settings.DEFAULT_SNAPSHOT_REQUIRED_LENGTH

            file_mirrors = mirrors.get_list_of_mirrors(
                "meta", "snapshot.json", self._mirrors
            )

            file_mirror_errors = {}
            for file_mirror in file_mirrors:
                try:
                    temp_obj = download.download_file(
                        file_mirror,
                        length,
                        self._fetcher,
                        strict_required_length=False,
                    )

                    temp_obj.seek(0)
                    self._trusted_bundle.update_metadata(
                        temp_obj.read(), "snapshot"
                    )
                    return

                except Exception as exception:  # pylint:  disable=broad-except
                    file_mirror_errors[file_mirror] = exception

                finally:
                    if temp_obj:
                        temp_obj.close()

            raise exceptions.NoWorkingMirrorError(file_mirror_errors)

    def _load_targets(self) -> None:
        """
        TODO
        """
        self._load_delegation("targets", "root")

    def _load_delegation(self, targets_role: str, parent_role: str) -> None:
        """
        TODO
        """
        if not self._trusted_bundle.load_local_metadata(targets_role):
            targets_filename = f"{targets_role}.json"
            try:
                length = self._trusted_bundle.snapshot.signed.meta[
                    targets_filename
                ]["length"]
            except KeyError:
                length = settings.DEFAULT_TARGETS_REQUIRED_LENGTH

            # TODO: Check if exists locally

            file_mirrors = mirrors.get_list_of_mirrors(
                "meta", targets_filename, self._mirrors
            )

            file_mirror_errors = {}
            for file_mirror in file_mirrors:
                try:
                    temp_obj = download.download_file(
                        file_mirror,
                        length,
                        self._fetcher,
                        strict_required_length=False,
                    )

                    temp_obj.seek(0)
                    self._trusted_bundle.update_metadata(
                        temp_obj.read(), targets_role, parent_role
                    )
                    return

                except Exception as exception:  # pylint:  disable=broad-except
                    file_mirror_errors[file_mirror] = exception

                finally:
                    if temp_obj:
                        temp_obj.close()

            raise exceptions.NoWorkingMirrorError(file_mirror_errors)

    def _preorder_depth_first_walk(self, target_filepath) -> Dict:
        """
        TODO
        """

        target = None
        role_names = [("targets", "root")]
        visited_role_names = set()
        number_of_delegations = settings.MAX_NUMBER_OF_DELEGATIONS

        # Ensure the client has the most up-to-date version of 'targets.json'.
        # Raise 'exceptions.NoWorkingMirrorError' if the changed metadata
        # cannot be successfully downloaded and
        # 'exceptions.RepositoryError' if the referenced metadata is
        # missing.  Target methods such as this one are called after the
        # top-level metadata have been refreshed (i.e., updater.refresh()).
        # self._update_metadata_if_changed('targets')

        # Preorder depth-first traversal of the graph of target delegations.
        while (
            target is None and number_of_delegations > 0 and len(role_names) > 0
        ):

            # Pop the role name from the top of the stack.
            role_name, parent_role = role_names.pop(-1)
            self._load_delegation(role_name, parent_role)
            # Skip any visited current role to prevent cycles.
            if (role_name, parent_role) in visited_role_names:
                msg = f"Skipping visited current role {role_name}"
                logger.debug(msg)
                continue

            # The metadata for 'role_name' must be downloaded/updated before
            # its targets, delegations, and child roles can be inspected.
            # self._metadata['current'][role_name] is currently missing.
            # _refresh_targets_metadata() does not refresh 'targets.json', it
            # expects _update_metadata_if_changed() to have already refreshed
            # it, which this function has checked above.
            # self._refresh_targets_metadata(role_name,
            #     refresh_all_delegated_roles=False)

            role_metadata = self._trusted_bundle[role_name]
            target = role_metadata.signed.targets.get(target_filepath)

            # After preorder check, add current role to set of visited roles.
            visited_role_names.add((role_name, parent_role))

            # And also decrement number of visited roles.
            number_of_delegations -= 1
            delegations = role_metadata.signed.delegations
            child_roles = delegations.get("roles", [])

            if target is None:

                child_roles_to_visit = []
                # NOTE: This may be a slow operation if there are many
                # delegated roles.
                for child_role in child_roles:
                    child_role_name = _visit_child_role(
                        child_role, target_filepath
                    )

                    if (
                        child_role["terminating"]
                        and child_role_name is not None
                    ):
                        msg = (
                            f"Adding child role {child_role_name}.\n",
                            "Not backtracking to other roles.",
                        )
                        logger.debug(msg)
                        role_names = []
                        child_roles_to_visit.append(
                            (child_role_name, role_name)
                        )
                        break

                    if child_role_name is None:
                        msg = f"Skipping child role {child_role_name}"
                        logger.debug(msg)

                    else:
                        msg = f"Adding child role {child_role_name}"
                        logger.debug(msg)
                        child_roles_to_visit.append(
                            (child_role_name, role_name)
                        )

                # Push 'child_roles_to_visit' in reverse order of appearance
                # onto 'role_names'.  Roles are popped from the end of
                # the 'role_names' list.
                child_roles_to_visit.reverse()
                role_names.extend(child_roles_to_visit)

            else:
                msg = f"Found target in current role {role_name}"
                logger.debug(msg)

        if (
            target is None
            and number_of_delegations == 0
            and len(role_names) > 0
        ):
            msg = (
                f"{len(role_names)}  roles left to visit, ",
                "but allowed to visit at most ",
                f"{settings.MAX_NUMBER_OF_DELEGATIONS}",
                " delegations.",
            )
            logger.debug(msg)

        return {"filepath": target_filepath, "fileinfo": target}


def _visit_child_role(child_role: Dict, target_filepath: str) -> str:
    """
    <Purpose>
      Non-public method that determines whether the given 'target_filepath'
      is an allowed path of 'child_role'.

      Ensure that we explore only delegated roles trusted with the target.  The
      metadata for 'child_role' should have been refreshed prior to this point,
      however, the paths/targets that 'child_role' signs for have not been
      verified (as intended).  The paths/targets that 'child_role' is allowed
      to specify in its metadata depends on the delegating role, and thus is
      left to the caller to verify.  We verify here that 'target_filepath'
      is an allowed path according to the delegated 'child_role'.

      TODO: Should the TUF spec restrict the repository to one particular
      algorithm?  Should we allow the repository to specify in the role
      dictionary the algorithm used for these generated hashed paths?

    <Arguments>
      child_role:
        The delegation targets role object of 'child_role', containing its
        paths, path_hash_prefixes, keys, and so on.

      target_filepath:
        The path to the target file on the repository. This will be relative to
        the 'targets' (or equivalent) directory on a given mirror.

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      If 'child_role' has been delegated the target with the name
      'target_filepath', then we return the role name of 'child_role'.

      Otherwise, we return None.
    """

    child_role_name = child_role["name"]
    child_role_paths = child_role.get("paths")
    child_role_path_hash_prefixes = child_role.get("path_hash_prefixes")

    if child_role_path_hash_prefixes is not None:
        target_filepath_hash = _get_target_hash(target_filepath)
        for child_role_path_hash_prefix in child_role_path_hash_prefixes:
            if not target_filepath_hash.startswith(child_role_path_hash_prefix):
                continue

            return child_role_name

    elif child_role_paths is not None:
        # Is 'child_role_name' allowed to sign for 'target_filepath'?
        for child_role_path in child_role_paths:
            # A child role path may be an explicit path or glob pattern (Unix
            # shell-style wildcards).  The child role 'child_role_name' is
            # returned if 'target_filepath' is equal to or matches
            # 'child_role_path'. Explicit filepaths are also considered
            # matches. A repo maintainer might delegate a glob pattern with a
            # leading path separator, while the client requests a matching
            # target without a leading path separator - make sure to strip any
            # leading path separators so that a match is made.
            # Example: "foo.tgz" should match with "/*.tgz".
            if fnmatch.fnmatch(
                target_filepath.lstrip(os.sep), child_role_path.lstrip(os.sep)
            ):
                logger.debug(
                    "Child role "
                    + repr(child_role_name)
                    + " is allowed to sign for "
                    + repr(target_filepath)
                )

                return child_role_name

            logger.debug(
                "The given target path "
                + repr(target_filepath)
                + " does not match the trusted path or glob pattern: "
                + repr(child_role_path)
            )
            continue

    else:
        # 'role_name' should have been validated when it was downloaded.
        # The 'paths' or 'path_hash_prefixes' fields should not be missing,
        # so we raise a format error here in case they are both missing.
        raise exceptions.FormatError(
            repr(child_role_name) + " "
            'has neither a "paths" nor "path_hash_prefixes".  At least'
            " one of these attributes must be present."
        )

    return None


def _check_file_length(file_object, trusted_file_length):
    """
    TODO
    """
    file_object.seek(0, 2)
    observed_length = file_object.tell()

    # Return and log a message if the length 'file_object' is equal to
    # 'trusted_file_length', otherwise raise an exception.  A hard check
    # ensures that a downloaded file strictly matches a known, or trusted,
    # file length.
    if observed_length != trusted_file_length:
        raise exceptions.DownloadLengthMismatchError(
            trusted_file_length, observed_length
        )


def _check_hashes_obj(file_object, trusted_hashes):
    """
    TODO
    """
    for algorithm, trusted_hash in trusted_hashes.items():
        digest_object = sslib_hash.digest_fileobject(file_object, algorithm)

        computed_hash = digest_object.hexdigest()

        # Raise an exception if any of the hashes are incorrect.
        if trusted_hash != computed_hash:
            raise sslib_exceptions.BadHashError(trusted_hash, computed_hash)

        logger.info(
            "The file's " + algorithm + " hash is" " correct: " + trusted_hash
        )


def _get_target_hash(target_filepath, hash_function="sha256"):
    """
    TODO
    """
    # Calculate the hash of the filepath to determine which bin to find the
    # target.  The client currently assumes the repository (i.e., repository
    # tool) uses 'hash_function' to generate hashes and UTF-8.
    digest_object = sslib_hash.digest(hash_function)
    encoded_target_filepath = target_filepath.encode("utf-8")
    digest_object.update(encoded_target_filepath)
    target_filepath_hash = digest_object.hexdigest()

    return target_filepath_hash


def neither_403_nor_404(mirror_error):
    """
    TODO
    """
    if isinstance(mirror_error, exceptions.FetcherHTTPError):
        if mirror_error.status_code in {403, 404}:
            return False
    return True
