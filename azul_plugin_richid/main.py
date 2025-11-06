"""Analyse rich header information from Microsoft PE files."""

import binascii

from azul_runner import (
    BinaryPlugin,
    Feature,
    FeatureValue,
    Job,
    State,
    add_settings,
    cmdline_run,
)

from . import richid


class AzulPluginRichId(BinaryPlugin):
    """Analyse rich header information from Microsoft PE files."""

    CONTACT = "ASD's ACSC"
    VERSION = "2025.03.19"
    SETTINGS = add_settings(
        filter_data_types={
            "content": [
                # Windows exe
                "executable/windows/pe",
                "executable/windows/pe32",
                "executable/windows/pe64",
                "executable/windows/dll",
                "executable/windows/dll32",
                "executable/windows/dll64",
                "executable/windows/dos",
                "executable/windows/com",
                # Non windows exe
                "executable/dll32",
                "executable/pe32",
            ]
        }
    )
    FEATURES = [
        Feature(name="pe_rich_mask", desc="Rich header XOR mask / checksum used", type=str),
        Feature(name="pe_rich_checksum", desc="Recalculated Rich header checksum", type=str),
        Feature(name="pe_rich_entry_count", desc="Count of objects for labelled compid/product", type=int),
        Feature(name="pe_rich_product", desc="Compiler/linker referenced in Rich entry", type=str),
        Feature(name="pe_rich_linker", desc="Final linker used as recorded by the Rich header", type=str),
        Feature(name="pe_rich_compid", desc="Rich header entry compid/type field", type=int),
        Feature(name="processing_failure", desc="Plugin is not able to handle the requested binary", type=str),
        Feature(name="tag", desc="Any informational label about the binary", type=str),
    ]

    def execute(self, job: Job):
        """Search the file for Rich Header and parses the details into features."""
        features = {}
        data = job.get_data()
        buf = data.read(8000)
        # If there aren't at least 48 bytes the file can't be a PE because it's smaller than the PE header.
        if len(buf) < 48:
            return State(State.Label.OPT_OUT, message="Not enough bytes for PE header.")
        # Check PE offset for legitimate header
        # validate that it's not a DOS file
        lfanew = (buf[0x3C + 3] << 24) | (buf[0x3C + 2] << 16) | (buf[0x3C + 1] << 8) | (buf[0x3C])
        if lfanew == 0:
            return State(State.Label.OPT_OUT, message="No PE header found.")
        if lfanew > 0:
            if lfanew + 1 > len(buf):
                return State(State.Label.OPT_OUT, message="PE header is in invalid location.")
            if buf[lfanew] != ord("P") or buf[lfanew + 1] != ord("E"):
                return State(State.Label.OPT_OUT, message="PE magic missing.")

        try:
            bytemask, objlist = richid.parse(buf)
            checksum = richid.checksum(buf)
        except richid.NoRichException:
            return State.Label.OPT_OUT
        except richid.ParseError:
            self.add_feature_values("processing_failure", "unable_to_parse_rich_header")
            return

        features["pe_rich_mask"] = "0x" + binascii.hexlify(bytemask[::-1]).decode("utf-8")
        features["pe_rich_checksum"] = "0x" + binascii.hexlify(checksum[::-1]).decode("utf-8")
        if bytemask != checksum:
            features["tag"] = "rich_checksum_mismatch"

        # map the rich details to features
        for rid in objlist:
            features.setdefault("pe_rich_compid", []).append(rid["compid"])
            name = rid.get("entrytype", str(rid["typeid"]))
            if rid["prodid"]:
                name = "%s [%s]" % (name, rid.get("product", str(rid["prodid"])))

            features.setdefault("pe_rich_entry_count", []).append(FeatureValue(rid["refcount"], label=name))
            if "product" in rid:
                features.setdefault("pe_rich_product", []).append(FeatureValue(rid["product"]))
            # last entry (since VS2007) is Linker
            if rid.get("entrytype") == "Linker" and "product" in rid:
                features["pe_rich_linker"] = rid["product"]

        self.add_many_feature_values(features)


def main():
    """Run the plugin via the command-line."""
    cmdline_run(plugin=AzulPluginRichId)


if __name__ == "__main__":
    main()
