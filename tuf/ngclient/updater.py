# Copyright 2020, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""TUF client workflow implementation.
"""

import logging
import os
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib import parse

from securesystemslib import util as sslib_util

from tuf import exceptions
from tuf.api.metadata import Targets
from tuf.ngclient._internal import (
    download,
    requests_fetcher,
    trusted_metadata_set,
)
from tuf.ngclient.config import UpdaterConfig
from tuf.ngclient.fetcher import FetcherInterface

logger = logging.getLogger(__name__)


class Updater:
    """
    An implemetation of the TUF client workflow.
    Provides a public API for integration in client applications.
    """

    def __init__(
        self,
        repository_dir: str,
        metadata_base_url: str,
        target_base_url: Optional[str] = None,
        fetcher: Optional[FetcherInterface] = None,
        config: Optional[UpdaterConfig] = None,
    ):
        """
        Args:
            repository_dir: Local metadata directory. Directory must be
                writable and it must contain at least a root.json file.
            metadata_base_url: Base URL for all remote metadata downloads
            target_base_url: Optional; Default base URL for all remote target
                downloads. Can be individually set in download_target()
            fetcher: Optional; FetcherInterface implementation used to download
                both metadata and targets. Default is RequestsFetcher

        Raises:
            OSError: Local root.json cannot be read
            RepositoryError: Local root.json is invalid
        """
        self._dir = repository_dir
        self._metadata_base_url = _ensure_trailing_slash(metadata_base_url)
        if target_base_url is None:
            self._target_base_url = None
        else:
            self._target_base_url = _ensure_trailing_slash(target_base_url)

        # Read trusted local root metadata
        data = self._load_local_metadata("root")
        self._trusted_set = trusted_metadata_set.TrustedMetadataSet(data)

        if fetcher is None:
            self._fetcher = requests_fetcher.RequestsFetcher()
        else:
            self._fetcher = fetcher

        self.config = config or UpdaterConfig()

    def refresh(self) -> None:
        """
        This method downloads, verifies, and loads metadata for the top-level
        roles in the specified order (root -> timestamp -> snapshot -> targets)
        The expiration time for downloaded metadata is also verified.

        The metadata for delegated roles are not refreshed by this method, but
        by the method that returns targetinfo (i.e.,
        get_one_valid_targetinfo()).

        The refresh() method should be called by the client before any target
        requests.

        Raises:
            OSError: New metadata could not be written to disk
            RepositoryError: Metadata failed to verify in some way
            TODO: download-related errors
        """

        self._load_root()
        self._load_timestamp()
        self._load_snapshot()
        self._load_targets("targets", "root")

    def get_one_valid_targetinfo(
        self, target_path: str
    ) -> Union[Dict[str, Any], None]:
        """
        Returns the target information for a target identified by target_path.

        As a side-effect this method downloads all the additional (delegated
        targets) metadata required to return the target information.

        Args:
            target_path: A target identifier that is a path-relative-URL string
                (https://url.spec.whatwg.org/#path-relative-url-string).
                Typically this is also the unix file path of the eventually
                downloaded file.

        Raises:
            OSError: New metadata could not be written to disk
            RepositoryError: Metadata failed to verify in some way
            TODO: download-related errors
        """
        targetinfo, dummy = self._preorder_depth_first_walk(
            target_path, set(), ("targets", "root"), self.config.max_delegations
        )
        return targetinfo

    @staticmethod
    def updated_targets(
        targets: List[Dict[str, Any]], destination_directory: str
    ) -> List[Dict[str, Any]]:
        """
        After the client has retrieved the target information for those targets
        they are interested in updating, they would call this method to
        determine which targets have changed from those saved locally on disk.
        All the targets that have changed are returned in a list.  From this
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
            target_fileinfo: "TargetFile" = target["fileinfo"]

            target_filepath = os.path.join(destination_directory, filepath)

            if target_filepath in updated_targetpaths:
                continue

            try:
                with open(target_filepath, "rb") as target_file:
                    target_fileinfo.verify_length_and_hashes(target_file)
            # If the file does not exist locally or length and hashes
            # do not match, append to updated targets.
            except (OSError, exceptions.LengthOrHashMismatchError):
                updated_targets.append(target)
                updated_targetpaths.append(target_filepath)

        return updated_targets

    def download_target(
        self,
        targetinfo: Dict,
        destination_directory: str,
        target_base_url: Optional[str] = None,
    ):
        """
        Download target specified by 'targetinfo' into 'destination_directory'.

        Args:
            targetinfo: data received from get_one_valid_targetinfo() or
                updated_targets().
            destination_directory: existing local directory to download into.
                Note that new directories may be created inside
                destination_directory as required.
            target_base_url: Optional; Base URL used to form the final target
                download URL. Default is the value provided in Updater()

        Raises:
            TODO: download-related errors
            TODO: file write errors
        """
        if target_base_url is None and self._target_base_url is None:
            raise ValueError(
                "target_base_url must be set in either download_target() or "
                "constructor"
            )
        if target_base_url is None:
            target_base_url = self._target_base_url
        else:
            target_base_url = _ensure_trailing_slash(target_base_url)

        target_filepath = targetinfo["filepath"]
        target_fileinfo: "TargetFile" = targetinfo["fileinfo"]
        full_url = parse.urljoin(target_base_url, target_filepath)

        with download.download_file(
            full_url, target_fileinfo.length, self._fetcher
        ) as target_file:
            try:
                target_fileinfo.verify_length_and_hashes(target_file)
            except exceptions.LengthOrHashMismatchError as e:
                raise exceptions.RepositoryError(
                    f"{target_filepath} length or hashes do not match"
                ) from e

            filepath = os.path.join(destination_directory, target_filepath)
            sslib_util.persist_temp_file(target_file, filepath)

    def _download_metadata(
        self, rolename: str, length: int, version: Optional[int] = None
    ) -> bytes:
        """Download a metadata file and return it as bytes"""
        if version is None:
            filename = f"{rolename}.json"
        else:
            filename = f"{version}.{rolename}.json"
        url = parse.urljoin(self._metadata_base_url, filename)
        return download.download_bytes(
            url,
            length,
            self._fetcher,
            strict_required_length=False,
        )

    def _load_local_metadata(self, rolename: str) -> bytes:
        with open(os.path.join(self._dir, f"{rolename}.json"), "rb") as f:
            return f.read()

    def _persist_metadata(self, rolename: str, data: bytes):
        with open(os.path.join(self._dir, f"{rolename}.json"), "wb") as f:
            f.write(data)

    def _load_root(self) -> None:
        """Load remote root metadata.

        Sequentially load and persist on local disk every newer root metadata
        version available on the remote.
        """

        # Update the root role
        lower_bound = self._trusted_set.root.signed.version + 1
        upper_bound = lower_bound + self.config.max_root_rotations

        for next_version in range(lower_bound, upper_bound):
            try:
                data = self._download_metadata(
                    "root", self.config.root_max_length, next_version
                )
                self._trusted_set.update_root(data)
                self._persist_metadata("root", data)

            except exceptions.FetcherHTTPError as exception:
                if exception.status_code not in {403, 404}:
                    raise
                # 404/403 means current root is newest available
                break

        # Verify final root
        self._trusted_set.root_update_finished()

    def _load_timestamp(self) -> None:
        """Load local and remote timestamp metadata"""
        try:
            data = self._load_local_metadata("timestamp")
            self._trusted_set.update_timestamp(data)
        except (OSError, exceptions.RepositoryError) as e:
            # Local timestamp does not exist or is invalid
            logger.debug("Failed to load local timestamp %s", e)

        # Load from remote (whether local load succeeded or not)
        data = self._download_metadata(
            "timestamp", self.config.timestamp_max_length
        )
        self._trusted_set.update_timestamp(data)
        self._persist_metadata("timestamp", data)

    def _load_snapshot(self) -> None:
        """Load local (and if needed remote) snapshot metadata"""
        try:
            data = self._load_local_metadata("snapshot")
            self._trusted_set.update_snapshot(data)
            logger.debug("Local snapshot is valid: not downloading new one")
        except (OSError, exceptions.RepositoryError) as e:
            # Local snapshot does not exist or is invalid: update from remote
            logger.debug("Failed to load local snapshot %s", e)

            metainfo = self._trusted_set.timestamp.signed.meta["snapshot.json"]
            length = metainfo.length or self.config.snapshot_max_length
            version = None
            if self._trusted_set.root.signed.consistent_snapshot:
                version = metainfo.version

            data = self._download_metadata("snapshot", length, version)
            self._trusted_set.update_snapshot(data)
            self._persist_metadata("snapshot", data)

    def _load_targets(self, role: str, parent_role: str) -> None:
        """Load local (and if needed remote) metadata for 'role'."""
        try:
            data = self._load_local_metadata(role)
            self._trusted_set.update_delegated_targets(data, role, parent_role)
            logger.debug("Local %s is valid: not downloading new one", role)
        except (OSError, exceptions.RepositoryError) as e:
            # Local 'role' does not exist or is invalid: update from remote
            logger.debug("Failed to load local %s: %s", role, e)

            metainfo = self._trusted_set.snapshot.signed.meta[f"{role}.json"]
            length = metainfo.length or self.config.targets_max_length
            version = None
            if self._trusted_set.root.signed.consistent_snapshot:
                version = metainfo.version

            data = self._download_metadata(role, length, version)
            self._trusted_set.update_delegated_targets(data, role, parent_role)
            self._persist_metadata(role, data)

    def _preorder_depth_first_walk(
        self,
        target_filepath: str,
        visited_role_names: Set[str],
        current_role_pair: List[Tuple[str, ...]],
        number_of_delegations: int,
    ) -> Tuple[Union[Dict[str, Any], None], bool]:
        """
        Interrogates the tree of target delegations in order of appearance
        (which implicitly order trustworthiness), and returns the matching
        target found in the most trusted role.
        """
        targetinfo = None
        terminated = False
        # Preorder depth-first traversal of the graph of target delegations.
        if number_of_delegations <= 0:
            return targetinfo, terminated

        # Pop the role name from the top of the stack.
        role_name, parent_role = current_role_pair

        # The metadata for 'role_name' must be downloaded/updated before
        # its targets, delegations, and child roles can be inspected.
        self._load_targets(role_name, parent_role)
        role_metadata: Targets = self._trusted_set[role_name].signed
        target = role_metadata.targets.get(target_filepath)

        if target is not None:
            logger.debug("Found target in current role %s", role_name)
            targetinfo = {"filepath": target_filepath, "fileinfo": target}
            return targetinfo, terminated

        # After preorder check, add current role to set of visited roles.
        visited_role_names.add((role_name, parent_role))

        # And also decrement number of visited roles.
        number_of_delegations -= 1
        if role_metadata.delegations is not None:
            for child_role in role_metadata.delegations.roles:
                # Skip any visited current role to prevent cycles.
                if (child_role.name, parent_role) in visited_role_names:
                    continue

                if child_role.is_in_trusted_paths(target_filepath):

                    targetinfo, terminated = self._preorder_depth_first_walk(
                        target_filepath,
                        visited_role_names,
                        (child_role.name, role_name),
                        number_of_delegations,
                    )

                    if child_role.terminating or terminated:
                        terminated = True
                        logger.debug("Not backtracking to other roles.")
                        break

        return targetinfo, terminated


def _ensure_trailing_slash(url: str):
    """Return url guaranteed to end in a slash"""
    return url if url.endswith("/") else f"{url}/"
