from binaryninja.function import Function, DisassemblySettings
from binaryninja.enums import DisassemblyOption
from binaryninja.lineardisassembly import LinearViewObject, LinearViewCursor, \
                                          LinearDisassemblyLine
from binaryninja import BinaryView


class Pseudo_C:

    def __init__(self, bv: BinaryView, func: Function) -> None:
        self.bv = bv
        self.func = func

    def get_c_source(self) -> list[str]:
        '''Returns a list of strings representing the C source code for the
        function.'''
        lines: list[str] = []
        settings: DisassemblySettings = DisassemblySettings()
        settings.set_option(DisassemblyOption.ShowAddress, False)

        linear_view: LinearViewObject = LinearViewObject.language_representation(
            self.bv, settings)
        cursor_end: LinearViewCursor = LinearViewCursor(linear_view)
        cursor_end.seek_to_address(self.func.highest_address)

        body: list[
            LinearDisassemblyLine] = self.bv.get_next_linear_disassembly_lines(
                cursor_end)
        cursor_end.seek_to_address(self.func.highest_address)

        header: list[
            LinearDisassemblyLine] = self.bv.get_previous_linear_disassembly_lines(
                cursor_end)

        for line in header:
            lines.append(str(line))
        for line in body:
            lines.append(str(line))
        return lines
