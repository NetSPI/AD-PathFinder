from .base import BaseDisplayHandler
from ..constants import DisplaySymbols


class SharedGraphPathDisplayHandler(BaseDisplayHandler):
    def display(self, results, category_color, category, content, count, reset_color):
        self._emit_heading(category_color, category, content, count, reset_color)

        total_items = len(results)
        for index, (sid, item) in enumerate(results.items()):
            if total_items > 1 and index > 0:
                self._emit("", content)

            description = item.get('description') if isinstance(item, dict) else item
            description = str(description) if description is not None else ''
            display_name = self.sid_mapper.get_display_name(sid)
            self._emit(f"{DisplaySymbols.MAIN_ITEM}{display_name}", content)
            for line in description.split('\n'):
                node_chain = self._node_chain(line)
                if node_chain:
                    self._emit(f"        {node_chain}", content)

        return content

    def _node_chain(self, line):
        line = line.strip()
        if not line:
            return ''
        path, scope = self._split_scope(line)
        tokens = self._tokens(path)
        scope_tokens = self._tokens(scope)

        chain = " > ".join(tokens)
        if not scope_tokens:
            return chain

        path_nodes = {
            self._normalize_node(token) for token in self._node_tokens(tokens)
        }
        if all(self._normalize_node(token) in path_nodes
               for token in self._node_tokens(scope_tokens)):
            return chain

        return f"{chain} | {' > '.join(scope_tokens)}"

    def _split_scope(self, line):
        path, sep, scope = line.partition(' | ')
        return path.strip(), scope.strip() if sep else ''

    def _tokens(self, chain):
        tokens = []
        for token in [part.strip() for part in chain.split(' -> ')]:
            if not token:
                continue
            tokens.append(token)
        return tokens

    def _node_tokens(self, tokens):
        if not tokens:
            return []
        start = 0 if len(tokens) % 2 == 1 else 1
        return [
            token for index, token in enumerate(tokens)
            if index >= start and (index - start) % 2 == 0
        ]

    def _normalize_node(self, node):
        node = (node or '').strip().lower()
        for wrapper in ('mssql_database(', 'sccm_site('):
            if node.startswith(wrapper) and node.endswith(')'):
                return node[len(wrapper):-1]
        return node
