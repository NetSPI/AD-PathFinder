from colorama import Style


class BaseDisplayHandler:
    def __init__(self, suppress_terminal_output=False, check_instance=None, sid_mapper=None):
        self.suppress_terminal_output = suppress_terminal_output
        self.check_instance = check_instance
        self.sid_mapper = sid_mapper
        self.reset_color = ""

    def _emit_heading(self, category_color, category, content, count, reset_color):
        if not self.suppress_terminal_output:
            print(f"\n  {Style.BRIGHT}{category_color}{category}: {count}{reset_color}")
        content.append(f"\n  {category}: {count}")

    def _emit(self, line, content):
        if not self.suppress_terminal_output:
            print(line)
        content.append(line)

    def _output_line(self, line, content):
        if not self.suppress_terminal_output:
            print(f"{self.reset_color}{line}")
        content.append(line)

    def display(self, results, category_color, category, content, count, reset_color):
        raise NotImplementedError
