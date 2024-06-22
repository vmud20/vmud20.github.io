import logging
import platform
from tree_sitter import Language, Parser, Node
from tree_sitter_languages import get_language, get_parser


class ASTParser:
    def __init__(self, code, language):
        # if platform.system() == "Darwin":
        #     library_path = "lib/languages-macos.so"
        # elif platform.system() == "Linux":
        #     library_path = "lib/languages-linux.so"
        # else:
        #     logging.fatal(f"Not supported system: {platform.system()}")
        #     return
        # self.LANGUAGE = Language(library_path, language)
        # self.parser = Parser()
        # self.parser.set_language(self.LANGUAGE)
        self.LANGUAGE = get_language(language)
        self.parser = get_parser(language)
        if isinstance(code, str):
            self.root = self.parser.parse(bytes(code, "utf-8")).root_node
        else:
            self.root = self.parser.parse(code).root_node

    @staticmethod
    def children_by_type_name(node, type):
        node_list = []
        for child in node.named_children:
            if child.type == type:
                node_list.append(child)
        return node_list

    @staticmethod
    def child_by_type_name(node, type):
        for child in node.named_children:
            if child.type == type:
                return child
        return None

    def query_oneshot(self, query_str):
        query = self.LANGUAGE.query(query_str)
        captures = query.captures(self.root)
        result = None
        for capture in captures:
            result = capture[0]
            break
        return result

    def query(self, query_str):
        try:
            query = self.LANGUAGE.query(query_str)
            captures = query.captures(self.root)
        except Exception as e:
            return []
        return captures


if __name__ == "__main__":
    code = '''/**
    * @param half_horiz Half horizontal resolution (0 or 1)
    * @param half_vert Half vertical resolution (0 or 1)
    */
    static int mm_decode_intra(MmContext * s, int half_horiz, int half_vert)
    {
        int x = 0, y = 0;

        while (bytestream2_get_bytes_left(&s->gb) > 0) {
            int run_length, color;

            if (y >= s->avctx->height)
                return 0;
            if(!(!bytestream2_get_byte(&s->gb)))
            return 1;
            color = bytestream2_get_byte(&s->gb);
            if (color & 0x80) {
                run_length = 1;
            }else{
                run_length = (color & 0x7f) + 2;
                color = bytestream2_get_byte(&s->gb);
            }

            if (half_horiz)
                run_length *=2;

            if (color) {
                memset(s->frame->data[0] + y*s->frame->linesize[0] + x, color, run_length);
                if (half_vert)
                    memset(s->frame->data[0] + (y+1)*s->frame->linesize[0] + x, color, run_length);
            }
            x+= run_length;

            if (x >= s->avctx->width) {
                x=0;
                y += 1 + half_vert;
            }
        }

        return 0;
    }
    '''
    root = ASTParser(code, language="cpp")
    children = ASTParser.children_by_type_name(root, "comparison_operator")
    for child in children:
        print(child)

    
