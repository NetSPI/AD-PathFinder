from colorama import Style
from ..constants import DataTypes, DisplaySymbols


class SimpleDisplayHandler:
    def __init__(self, suppress_terminal_output=False, check_instance=None, sid_mapper=None):
        self.suppress_terminal_output = suppress_terminal_output
        self.check_instance = check_instance
        self.sid_mapper = sid_mapper
        self.reset_color = ""

    def _format_entity_display(self, item_name, item_data):
        display_name = self.sid_mapper.get_display_name(item_name)
        display_name = self._format_with_password(display_name, item_name)

        if isinstance(item_data, dict) and item_data.get('inline_description'):
            return f"{DisplaySymbols.MAIN_ITEM}{display_name} {item_data['inline_description']}", None

        main_line = f"{DisplaySymbols.MAIN_ITEM}{display_name}"

        if isinstance(item_data, dict):
            description = item_data.get('description')
        else:
            description = item_data if item_data and item_data != display_name else None

        if not description:
            return main_line, None

        description = str(description)
        lines = description.split('\n')
        formatted_lines = []
        for line in lines:
            stripped = line.lstrip()
            if any(stripped.startswith(char) for char in ['└─', '├─', '│']):
                formatted_lines.append(f"        {line}")
            else:
                formatted_lines.append(f"{DisplaySymbols.SUB_ITEM}{line}")

        return main_line, '\n'.join(formatted_lines)

    def _format_with_password(self, display_name, entity_sid):
        if not self.check_instance:
            return display_name
        if not (hasattr(self.check_instance, 'REQUIRED_DATA') and
                DataTypes.WEAK_PASSWORD in self.check_instance.REQUIRED_DATA):
            return display_name
        if not hasattr(self.check_instance, 'account_analysis') or not self.check_instance.account_analysis:
            return display_name
        # only show passwords with explicit --unsafe-report flag
        if not (hasattr(self.check_instance.account_analysis, 'output_format') and
                self.check_instance.account_analysis.output_format == 'unsafe'):
            return display_name
        password_display = self.check_instance.get_password_display(entity_sid)
        if password_display is not None:
            return f"{display_name}:{password_display}"
        return display_name

    def _output_line(self, line, content):
        if not self.suppress_terminal_output:
            print(f"{self.reset_color}{line}")
        content.append(line)

    def display(self, results, category_color, category, content, count, reset_color):
        self.reset_color = reset_color

        if not self.suppress_terminal_output:
            print(f"\n  {Style.BRIGHT}{category_color}{category}: {count}{reset_color}")
        content.append(f"\n  {category}: {count}")

        for item_name, item_data in results.items():
            main_line, desc_line = self._format_entity_display(item_name, item_data)
            self._output_line(main_line, content)
            if desc_line:
                self._output_line(desc_line, content)

        return content
