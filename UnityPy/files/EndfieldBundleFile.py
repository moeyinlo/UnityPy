"""Read-only Endfield aggregate container, with ordinary UnityPy child files."""

from ..helpers.EndfieldBundle import decode_bundle
from ..streams import EndianBinaryReader
from .File import File


class EndfieldBundleFile(File):
    def __init__(self, reader, parent=None, name=None, is_dependency=False):
        super().__init__(parent, name, is_dependency)
        reader.Position = 0
        payload, nodes = decode_bundle(reader.read_bytes(reader.Length))
        self.read_files(EndianBinaryReader(payload), nodes)

    def save(self, *args, **kwargs):
        raise NotImplementedError("Writing Endfield aggregate bundles is not supported")
