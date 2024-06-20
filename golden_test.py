import contextlib
import io
import logging
import os
import tempfile

import machine
import translator
import pytest

# logger = logging.getLogger()
# logger.setLevel(logging.DEBUG)
# handler = logging.StreamHandler()
# formatter = logging.Formatter("%(levelname)-7s %(module)s:%(funcName)-13s %(message)s")
# handler.setFormatter(formatter)
# logger.addHandler(handler)

def normalize_whitespace(s):
    return ' '.join(s.split())

def ensure_newline_at_end(s):
    if not s.endswith('\n'):
        return s + '\n'
    return s

@pytest.mark.golden_test("golden/*.yml")
def test_translator_and_machine(golden, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    logger = logging.getLogger("golden_test")
    logger.setLevel(logging.DEBUG)

    with tempfile.TemporaryDirectory() as tmpdirname:
        source = os.path.join(tmpdirname, "source.myasm")
        input_stream = os.path.join(tmpdirname, "input.txt")
        target = os.path.join(tmpdirname, "target.o")

        with open(source, "w", encoding="utf-8") as file:
            file.write(golden["in_source"])
        with open(input_stream, "w", encoding="utf-8") as file:
            file.write(golden["in_stdin"])

        # stdout
        f = io.StringIO()
        with contextlib.redirect_stdout(f) as stdout:
            translator.main(source, target)
            print("============================================================")
            machine.main(target, input_stream)

        with open(target, encoding="utf-8") as file:
            code = file.read()

        assert ensure_newline_at_end(code) == ensure_newline_at_end(golden.out["out_code"])
        assert stdout.getvalue() == golden.out["out_stdout"]
        assert normalize_whitespace(caplog.text) == normalize_whitespace(golden.out["out_log"])
