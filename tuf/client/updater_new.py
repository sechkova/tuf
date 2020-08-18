#!/usr/bin/env python

"""
# TODO:
"""

#Imports
import tuf.api.metadata
import tuf.api.keys


class Updater:

  def __init__(self, repository_mirrors):

    # Load the trusted root metadata file.
    # FIXME: missing Root in metadata api
    self.trusted_root = metadata.Root.read_from_json('root.json')

    # FIXME: how to init role keyring from metadata?
    self.trusted_root_keyring = keys.KeyRing(self.trusted_root.roles['root']['threshold'], self.trusted_root.roles['root']['keys'])
    self.mirrors = repository_mirrors

    self.timestamp = metadata.Timestamp.read_from_json('timestamp.json')
    self.snapshot = metadata.Snapshot.read_from_json('snapshot.json')
    self.targets = metadata.Targets.read_from_json('targets.json')

    self.consistent_snapshot = False


  def refresh(self):
    """
    # TODO:
    """

    # 1. Update the root metadata file.
    self._update_root_metadata_file()
    
    # 2. Download the timestamp metadata file
    self._download_timestamp_metadata_file()

    # 3. Download snapshot metadata file, 
    self._download_snapshot_metadata_file()

    # 4. Download the top-level targets metadata file
    self._download_targets_metadata_file()




  #
  # def get_fileinfo
  #
  # def update()
  #
  # def check_for_update()


  def _update_root_metadata_file(self):
    # 1.1. Let N denote the version number of the trusted root metadata file.
    lower_bound = self.trusted_root.version
    upper_bound = lower_bound + tuf.settings.MAX_NUMBER_ROOT_ROTATIONS

    intermediate_root = None
    for next_version in range(lower_bound, upper_bound):
      # 1.2. Try downloading version N+1 of the root metadata file
      # up to some W number of bytes
      root_filename = _get_filename('root', version)
      file_mirrors = tuf.mirrors.get_list_of_mirrors('meta', root_filename,
              self.mirrors)

      file_object = None
      for file_mirror in file_mirrors:
        try:
          file_object = tuf.download.unsafe_download(file_mirror,
              tuf.settings.DEFAULT_ROOT_REQUIRED_LENGTH)
          file_object.seek(0)

          # FIXME: How to read tmp file objects
          intermediate_root = metadata.Root.read_from_json(file_object)
          intermediate_keyring = keys.KeyRing(intermediate_root.signed.roles['root']['threshold'],
                                              intermediate_root.signed.roles['root']['keys'])
          # 1.3. Check signatures
          intermediate_root.verify(self.trusted_root_keyring)
          intermediate_root.verify(intermediate_keyring)

          # 1.4. Check for a rollback attack.
          # 1.5. Note that the expiration of the new (intermediate) root metadata file does not matter yet,
          # because we will check for it in step 1.8.
          assert intermediate_root.signed.version >= self.trusted_root.version

          # 1.6. Set the trusted root metadata file to the new root metadata file.
          self.trusted_root_md = intermediate_root
          self.trusted_root = intermediate_root.signed

        except requests.exceptions.HTTPError as mirror_error:
          if mirror_error.response.status_code in {403, 404}:
            # 1.8. Check for a freeze attack.
            self._ensure_not_expired(self.trusted_root.as_dict(), 'root')
            break
          else:
            # TODO: do something
            raise
        except tuf.exceptions.BadSignatureError as exception:
          # TODO: do something
          raise
        except tuf.exceptions.BadVersionNumberError as exception:
          # TODO: do something
          raise

     # FIXME: write with consistent_snapshot
     self.trusted_root_md.write_to_json(trusted_root_filename)

     # 1.9. If the timestamp and / or snapshot keys have been rotated,
     # then delete the trusted timestamp and snapshot metadata files.
     if(self.trusted_root.roles['timestamp']['keys']) != intermediate_root.roles['timestamp']['keys']):
       # FIXME: use abstract storage
       # remove timestamp
     if(self.trusted_root.roles['snapshot']['keys']) != intermediate_root.roles['snapshot']['keys']):
       # FIXME: use abstract storage
       # remove snapshot

     # 1.10. Set whether consistent snapshots are used as per the trusted root metadata file
     self.consistent_snapshot = self.trusted_root.as_dict()['constitent_snapshot']




  def _download_timestamp_metadata_file(self):
    
    # 2. Download the timestamp metadata file, up to X number of bytes (because the size is unknown)
    timestamp_filename = 'timestamp.json'
    file_mirrors = tuf.mirrors.get_list_of_mirrors('meta', timestamp_filename,
            self.mirrors)

    file_object = None
    for file_mirror in file_mirrors:
      try:
        file_object = tuf.download.unsafe_download(file_mirror,
            tuf.settings.DEFAULT_TIMESTAMP_REQUIRED_LENGTH)
        file_object.seek(0)

        # 2.1. Check signatures. 
        new_timestamp = metadata.Timestamp.read_from_json(file_object)
        timestamp_keyring = keys.KeyRing(self.trusted_root.roles['timestamp']['threshold'],
                                            self.trusted_root.roles['timestamp']['keys'])
        new_timestamp.verify(timestamp_keyring)

        # 2.2. Check for a rollback attack.
        assert new_timestamp.signed.version >= self.timestamp.version

        # 2.3. Check for a freeze attack. 
        self._ensure_not_expired(new_timestamp.as_dict(), 'timestamp')

        new_timestamp.write_to_json()
        self.timestamp = new_timestamp

      except Exception:
        # TODO: do something
        raise



 def _download_snapshot_metadata_file(self):
   # 3. Download snapshot metadata file, up to either the number of bytes specified in the timestamp
   # metadata file, or some Y number of bytes
   snapshot_expected_version = self.timestamp.signed.meta['snapshot.json'].get('version')
   snapshot_expected_hash = self.timestamp.signed.meta['snapshot.json'].get('hash')

   snapshot_filename = self._get_filename('snapshot', snapshot_expected_version)
   file_mirrors = tuf.mirrors.get_list_of_mirrors('meta', snapshot_filename, self.mirrors)

   snapshot_upperlength = tuf.timestamp.signed.meta['snapshot.json'].get('length', tuf.settings.DEFAULT_SNAPSHOT_REQUIRED_LENGTH)

   file_object = None
   for file_mirror in file_mirrors:
     try:
       file_object = tuf.download.unsafe_download(file_mirror,
           snapshot_upperlength)
       file_object.seek(0)

       # FIXME: How to read tmp file objects
       new_snapshot = metadata.Snapshot.read_from_json(file_object)

       # 3.1. Check against timestamp metadata
       if snapshot_expected_hash is not None:
           self._check_hashes(file_object, snapshot_expected_hash)

       assert new_snapshot.signed.version == snapshot_expected_version

       # 3.2. Check signatures
       snapshot_keyring = keys.KeyRing(self.trusted_root.roles['snapshot']['threshold'],
                                       self.trusted_root.roles['snapshot']['keys'])
       new_snapshot.verify(snapshot_keyring)

       # 3.3. Check for a rollback attack.
       assert new_snapshot.signed.version >= self.snapshot.version   
       for target in self.snapshot.signed.meta:
         try:
           assert target['version'] <= new_snapshot.signed.meta[targets]['version']
         except KeyError:
           raise

       # 3.4. Check for a freeze attack. 
       self._ensure_not_expired(new_snapshot.as_dict(), 'snapshot')
      
       new_snapshot.write_to_json()
       self.snapshot = new_snapshot

     except Exception:
       # TODO: do something
       raise


  def _download_targets_metadata_file(self):
  
   targets_expected_version = self.snapshot.signed.meta['targets.json'].get('version')
   targets_expected_hash = self.snapshot.signed.meta['snapshot.json'].get('hash')
   targets_filename = self._get_filename('targets', targets_expected_version)
   targets_upperlength = tuf.snapshot.signed.meta['targets.json'].get('length', tuf.settings.DEFAULT_TARGETS_REQUIRED_LENGTH)
 
   file_mirrors = tuf.mirrors.get_list_of_mirrors('meta', targets_filename, self.mirrors)
   file_object = None
   for file_mirror in file_mirrors:
     try:
       file_object = tuf.download.unsafe_download(file_mirror,
           targets_upperlength)
       file_object.seek(0)

       # FIXME: How to read tmp file objects
       new_targets = metadata.Snapshot.read_from_json(file_object)

       # 4.1. Check against snapshot metadata.
       if targets_expected_hash is not None:
           self._check_hashes(file_object, targets_expected_hash)

       assert new_targets.signed.version == targets_expected_version

       # 4.2. Check for an arbitrary software attack
       targets_keyring = keys.KeyRing(self.trusted_root.roles['targets']['threshold'],
                                     self.trusted_root.roles['targets']['keys'])
       new_targets.verify(targets_keyring)

       # 4.3. Check for a freeze attack.
       self._ensure_not_expired(new_targets.as_dict(), 'targets')
      
       new_targets.write_to_json()
       self.targets = new_snapshot

     except Exception:
       # TODO: do something
       raise

    
       




