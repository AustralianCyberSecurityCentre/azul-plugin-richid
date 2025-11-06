"""RichID test suite - test the RichID plugin."""

from azul_runner import FV, Event, Filepath, JobResult, State, Uri, test_template

from azul_plugin_richid.main import AzulPluginRichId


class TestRichId(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginRichId

    def test_richid_rich_pefile(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "702e31ed1537c279459a255460f12f0f2863f973e121cd9194957f4f3e7b0994",
                        "Benign WIN32 EXE, python library executable python_mcp.exe",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="702e31ed1537c279459a255460f12f0f2863f973e121cd9194957f4f3e7b0994",
                        features={
                            "pe_rich_checksum": [FV("0xa572feb8")],
                            "pe_rich_compid": [
                                FV(65536),
                                FV(8111655),
                                FV(8615945),
                                FV(8681481),
                                FV(9336841),
                                FV(9533449),
                                FV(9664521),
                                FV(9730057),
                                FV(9795593),
                            ],
                            "pe_rich_entry_count": [
                                FV(1, label="ASM objects [VS2008 SP1 build 30729]"),
                                FV(1, label="C objects [VS2008 SP1 build 30729]"),
                                FV(1, label="Linker [VS2008 SP1 build 30729]"),
                                FV(1, label="Resource objects [VS2008 SP1 build 30729]"),
                                FV(2, label="C++ objects [VS2008 SP1 build 30729]"),
                                FV(2, label="Imports [VS2012 build 50727 / VS2005 build 50727]"),
                                FV(5, label="Imports [VS2008 SP1 build 30729]"),
                                FV(21, label="C objects [VS2008 SP1 build 30729]"),
                                FV(40, label="Total imports"),
                            ],
                            "pe_rich_linker": [FV("VS2008 SP1 build 30729")],
                            "pe_rich_mask": [FV("0xa572feb8")],
                            "pe_rich_product": [
                                FV("VS2008 SP1 build 30729"),
                                FV("VS2012 build 50727 / VS2005 build 50727"),
                            ],
                        },
                    )
                ],
            ),
        )

    def test_richid_dosfile(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "539fe0bd3e48f45708ab04be6ecd18d6091f0e4c44ab0dfd01abf14b1929c610",
                        "Malicious Windows DOS EXE, malware family CobaltStrikeBeacon.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(state=State(State.Label.OPT_OUT, message="PE magic missing.")),
        )

    def test_richid_small_file(self):
        result = self.do_execution(data_in=[("content", b"abcdefghijklmno")], verify_input_content=False)
        self.assertJobResult(
            result,
            JobResult(state=State(State.Label.OPT_OUT, message="Not enough bytes for PE header.")),
        )
