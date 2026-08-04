// Unity build: include simplecpp implementation directly since CGo only
// compiles .cpp files from the immediate package directory, not subdirs.
#include "vendored/simplecpp/simplecpp.cpp"

#include "cbm.h"
#include "preprocessor.h"
#include "vendored/simplecpp/simplecpp.h"

#include <climits>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <exception>
#include <fstream>
#include <iterator>
#include <limits>
#include <new>
#include <sstream>
#include <string>
#include <vector>

namespace {

static void set_status(CBMPreprocessStatus *status_out, CBMPreprocessStatus status) {
    if (status_out)
        *status_out = status;
}

static char *dup_string(const std::string &value) {
    char *out = static_cast<char *>(malloc(value.size() + 1));
    if (!out)
        return NULL;
    memcpy(out, value.c_str(), value.size() + 1);
    return out;
}

static void set_diagnostic(char **diagnostic_out, const std::string &diagnostic) {
    if (!diagnostic_out)
        return;
    *diagnostic_out = dup_string(diagnostic);
}

static void set_diagnostic_cstr(char **diagnostic_out, const char *diagnostic) noexcept {
    if (!diagnostic_out || !diagnostic)
        return;
    size_t len = strlen(diagnostic);
    char *copy = static_cast<char *>(malloc(len + 1));
    if (!copy)
        return;
    memcpy(copy, diagnostic, len + 1);
    *diagnostic_out = copy;
}

static bool is_name_char(char c) {
    unsigned char uc = static_cast<unsigned char>(c);
    return (uc >= 'a' && uc <= 'z') || (uc >= 'A' && uc <= 'Z') || (uc >= '0' && uc <= '9') ||
           uc == '_';
}

static bool matches_directive(const char *name, int len) {
    static const char *const directives[] = {
        "define", "undef", "include", "if",    "ifdef",   "ifndef",
        "elif",   "else",  "endif",   "error", "warning", NULL,
    };
    for (int i = 0; directives[i]; i++) {
        size_t dlen = strlen(directives[i]);
        if ((size_t)len == dlen && strncmp(name, directives[i], dlen) == 0)
            return true;
    }
    return false;
}

static bool source_has_preprocessor_work(const char *source, int source_len) {
    for (int i = 0; i < source_len; i++) {
        if (source[i] != '#')
            continue;
        bool line_prefix_is_space = true;
        for (int p = i - 1; p >= 0 && source[p] != '\n' && source[p] != '\r'; p--) {
            if (source[p] != ' ' && source[p] != '\t') {
                line_prefix_is_space = false;
                break;
            }
        }
        if (!line_prefix_is_space)
            continue;
        int j = i + 1;
        while (j < source_len && (source[j] == ' ' || source[j] == '\t'))
            j++;
        int start = j;
        while (j < source_len && is_name_char(source[j]))
            j++;
        if (j > start && matches_directive(source + start, j - start))
            return true;
    }
    return false;
}

static bool source_has_line_control(const char *source, int source_len) {
    for (int i = 0; i < source_len; i++) {
        if (source[i] != '#')
            continue;
        bool line_prefix_is_space = true;
        for (int p = i - 1; p >= 0 && source[p] != '\n' && source[p] != '\r'; p--) {
            if (source[p] != ' ' && source[p] != '\t') {
                line_prefix_is_space = false;
                break;
            }
        }
        if (!line_prefix_is_space)
            continue;
        int j = i + 1;
        while (j < source_len && (source[j] == ' ' || source[j] == '\t'))
            j++;
        static const char directive[] = "line";
        if (j + 4 <= source_len && strncmp(source + j, directive, 4) == 0 &&
            (j + 4 == source_len || !is_name_char(source[j + 4])))
            return true;
    }
    return false;
}

static unsigned int physical_line_count(const char *source, int source_len) {
    unsigned int count = 1;
    for (int i = 0; i < source_len; i++) {
        if (source[i] == '\n') {
            if (count == std::numeric_limits<unsigned int>::max())
                return 0;
            count++;
        }
    }
    return count;
}

static bool parse_generated_line_directive(const std::string &line, unsigned int *line_out,
                                           std::string *file_out) {
    static const std::string prefix = "#line ";
    if (line.compare(0, prefix.size(), prefix) != 0)
        return false;

    size_t pos = prefix.size();
    if (pos >= line.size() || line[pos] < '0' || line[pos] > '9')
        return false;
    unsigned int value = 0;
    while (pos < line.size() && line[pos] >= '0' && line[pos] <= '9') {
        unsigned int digit = static_cast<unsigned int>(line[pos] - '0');
        if (value > (std::numeric_limits<unsigned int>::max() - digit) / 10U)
            return false;
        value = value * 10U + digit;
        pos++;
    }
    if (value == 0 || pos + 3 > line.size() || line[pos] != ' ' || line[pos + 1] != '"' ||
        line.back() != '"')
        return false;

    *line_out = value;
    *file_out = line.substr(pos + 2, line.size() - pos - 3);
    return true;
}

static bool build_primary_source_line_map(const std::string &expanded,
                                          const std::string &entry_file,
                                          const std::string &primary_file,
                                          unsigned int source_line_count,
                                          std::vector<uint32_t> *map, std::string *diagnostic) {
    unsigned int logical_line = 1;
    const std::string normalized_primary = simplecpp::simplifyPath(primary_file);
    bool primary = simplecpp::simplifyPath(entry_file) == normalized_primary;
    size_t start = 0;

    for (;;) {
        size_t end = expanded.find('\n', start);
        std::string line =
            expanded.substr(start, end == std::string::npos ? std::string::npos : end - start);
        unsigned int directive_line = 0;
        std::string directive_file;
        if (line.compare(0, 6, "#line ") == 0) {
            if (!parse_generated_line_directive(line, &directive_line, &directive_file)) {
                *diagnostic = "malformed generated #line directive in preprocessor output";
                return false;
            }
            map->push_back(0);
            logical_line = directive_line;
            primary = simplecpp::simplifyPath(directive_file) == normalized_primary;
        } else if (!primary) {
            map->push_back(std::numeric_limits<uint32_t>::max());
            if (logical_line < std::numeric_limits<unsigned int>::max())
                logical_line++;
        } else {
            map->push_back(logical_line <= source_line_count ? logical_line : 0);
            if (logical_line < std::numeric_limits<unsigned int>::max())
                logical_line++;
        }

        if (end == std::string::npos)
            break;
        start = end + 1;
    }
    return true;
}

static const char *output_type_name(simplecpp::Output::Type type) {
    switch (type) {
    case simplecpp::Output::ERROR:
        return "ERROR";
    case simplecpp::Output::WARNING:
        return "WARNING";
    case simplecpp::Output::MISSING_HEADER:
        return "MISSING_HEADER";
    case simplecpp::Output::INCLUDE_NESTED_TOO_DEEPLY:
        return "INCLUDE_NESTED_TOO_DEEPLY";
    case simplecpp::Output::SYNTAX_ERROR:
        return "SYNTAX_ERROR";
    case simplecpp::Output::PORTABILITY_BACKSLASH:
        return "PORTABILITY_BACKSLASH";
    case simplecpp::Output::UNHANDLED_CHAR_ERROR:
        return "UNHANDLED_CHAR_ERROR";
    case simplecpp::Output::EXPLICIT_INCLUDE_NOT_FOUND:
        return "EXPLICIT_INCLUDE_NOT_FOUND";
    case simplecpp::Output::FILE_NOT_FOUND:
        return "FILE_NOT_FOUND";
    case simplecpp::Output::DUI_ERROR:
        return "DUI_ERROR";
    default:
        return "UNKNOWN";
    }
}

static bool output_is_fatal(const simplecpp::Output &out) {
    switch (out.type) {
    case simplecpp::Output::ERROR:
    case simplecpp::Output::INCLUDE_NESTED_TOO_DEEPLY:
    case simplecpp::Output::SYNTAX_ERROR:
    case simplecpp::Output::UNHANDLED_CHAR_ERROR:
    case simplecpp::Output::EXPLICIT_INCLUDE_NOT_FOUND:
    case simplecpp::Output::FILE_NOT_FOUND:
    case simplecpp::Output::DUI_ERROR:
    case simplecpp::Output::MISSING_HEADER:
        return true;
    case simplecpp::Output::WARNING:
    case simplecpp::Output::PORTABILITY_BACKSLASH:
    default:
        return false;
    }
}

static std::string output_location(const simplecpp::Output &out,
                                   const std::vector<std::string> &files) {
    std::ostringstream loc;
    if (out.location.fileIndex < files.size() && !files[out.location.fileIndex].empty())
        loc << files[out.location.fileIndex];
    else
        loc << "<input>";
    if (out.location.line > 0)
        loc << ":" << out.location.line;
    if (out.location.col > 0)
        loc << ":" << out.location.col;
    return loc.str();
}

static std::string diagnostic_atom(std::string value) {
    for (size_t i = 0; i < value.size(); i++) {
        unsigned char ch = static_cast<unsigned char>(value[i]);
        bool keep = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                    (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.';
        if (!keep)
            value[i] = '_';
    }
    return value;
}

static std::string fatal_output_summary(const simplecpp::OutputList &outputs,
                                        const std::vector<std::string> &files) {
    std::ostringstream summary;
    int count = 0;
    for (simplecpp::OutputList::const_iterator it = outputs.begin(); it != outputs.end(); ++it) {
        if (!output_is_fatal(*it))
            continue;
        if (count > 0)
            summary << "; ";
        std::string msg = it->msg;
        const std::string eval_prefix = "failed to evaluate #if condition, ";
        if (msg.compare(0, eval_prefix.size(), eval_prefix) == 0)
            msg.erase(0, eval_prefix.size());
        const std::string undefined_prefix = "undefined function-like macro invocation: ";
        size_t undefined_at = msg.find(undefined_prefix);
        if (undefined_at != std::string::npos) {
            msg = msg.substr(undefined_at + undefined_prefix.size());
            size_t paren_at = msg.find('(');
            if (paren_at != std::string::npos)
                msg.erase(paren_at);
            msg = "undefined_macro_" + msg;
        }
        summary << output_type_name(it->type) << "_" << diagnostic_atom(msg) << "_at_"
                << diagnostic_atom(output_location(*it, files));
        count++;
        if (count >= 6) {
            summary << "; additional fatal preprocessing diagnostics omitted";
            break;
        }
    }
    return summary.str();
}

} // namespace

extern "C" {

char *cbm_preprocess(const char *focus_source, int focus_source_len, const char *focus_filename,
                     const CBMPreprocessContext *context,
                     CBMPreprocessStatus *status_out, char **diagnostic_out,
                     uint32_t **primary_source_lines_out, size_t *expanded_line_count_out) {
    set_status(status_out, CBM_PREPROCESS_NO_DIRECTIVES);
    if (diagnostic_out)
        *diagnostic_out = NULL;
    if (primary_source_lines_out)
        *primary_source_lines_out = NULL;
    if (expanded_line_count_out)
        *expanded_line_count_out = 0;

    if (!focus_source || focus_source_len <= 0)
        return NULL;

    if (!context || !context->context_id || !context->context_id[0] || !context->entry_path ||
        !context->entry_path[0] || !context->standard || !context->standard[0] ||
        !focus_filename || !focus_filename[0]) {
        set_status(status_out, CBM_PREPROCESS_FAILED);
        set_diagnostic(diagnostic_out,
                       "CBM_PREPROCESS_CONTEXT_MISSING: exact translation-unit context is absent");
        return NULL;
    }

    if (!primary_source_lines_out || !expanded_line_count_out) {
        set_status(status_out, CBM_PREPROCESS_FAILED);
        set_diagnostic(diagnostic_out, "preprocessor expansion map outputs are required");
        return NULL;
    }
    std::string entry_storage;
    const char *entry_source = focus_source;
    int entry_source_len = focus_source_len;
    if (simplecpp::simplifyPath(context->entry_path) !=
        simplecpp::simplifyPath(focus_filename)) {
        std::ifstream input(context->entry_path, std::ios::binary);
        if (!input) {
            set_status(status_out, CBM_PREPROCESS_FAILED);
            set_diagnostic(diagnostic_out,
                           "CBM_PREPROCESS_ENTRY_READ_FAILED: consuming translation unit is unreadable");
            return NULL;
        }
        entry_storage.assign(std::istreambuf_iterator<char>(input),
                             std::istreambuf_iterator<char>());
        if (!input.eof() || entry_storage.size() > static_cast<size_t>(INT_MAX)) {
            set_status(status_out, CBM_PREPROCESS_FAILED);
            set_diagnostic(diagnostic_out,
                           "CBM_PREPROCESS_ENTRY_READ_FAILED: consuming translation unit read is incomplete or oversized");
            return NULL;
        }
        entry_source = entry_storage.data();
        entry_source_len = static_cast<int>(entry_storage.size());
    }
    if (entry_source_len <= 0) {
        set_status(status_out, CBM_PREPROCESS_FAILED);
        set_diagnostic(diagnostic_out,
                       "CBM_PREPROCESS_ENTRY_EMPTY: consuming translation unit is empty");
        return NULL;
    }
    if (source_has_line_control(entry_source, entry_source_len)) {
        set_status(status_out, CBM_PREPROCESS_FAILED);
        set_diagnostic(diagnostic_out,
                       "physical expansion mapping is undefined for input containing #line");
        return NULL;
    }

    try {
        simplecpp::DUI dui;
        if (context->defines) {
            for (int i = 0; context->defines[i]; i++)
                dui.defines.push_back(context->defines[i]);
        }
        if (context->undefines) {
            for (int i = 0; context->undefines[i]; i++)
                dui.undefined.insert(context->undefines[i]);
        }
        if (context->include_paths) {
            for (int i = 0; context->include_paths[i]; i++)
                dui.includePaths.push_back(context->include_paths[i]);
        }
        if (context->forced_includes) {
            for (int i = 0; context->forced_includes[i]; i++)
                dui.includes.push_back(context->forced_includes[i]);
        }
        dui.std = context->standard;

        simplecpp::OutputList outputs;
        std::vector<std::string> files;
        files.push_back(context->entry_path);

        simplecpp::TokenList rawtokens(entry_source, static_cast<std::size_t>(entry_source_len), files,
                                       files[0], &outputs);
        simplecpp::TokenList output(files);
        simplecpp::FileDataCache filedata = simplecpp::load(rawtokens, files, dui, &outputs);

        try {
            simplecpp::preprocess(output, rawtokens, files, filedata, dui, &outputs);
        } catch (...) {
            simplecpp::cleanup(filedata);
            throw;
        }

        std::string fatal = fatal_output_summary(outputs, files);
        if (!fatal.empty()) {
            simplecpp::cleanup(filedata);
            set_status(status_out, CBM_PREPROCESS_FAILED);
            set_diagnostic(diagnostic_out, fatal);
            return NULL;
        }

        std::string result = output.stringify();
        std::vector<uint32_t> primary_source_lines;
        std::string map_diagnostic;
        unsigned int source_lines = physical_line_count(focus_source, focus_source_len);
        if (source_lines == 0 ||
            !build_primary_source_line_map(result, context->entry_path, focus_filename,
                                           source_lines, &primary_source_lines,
                                           &map_diagnostic)) {
            simplecpp::cleanup(filedata);
            set_status(status_out, CBM_PREPROCESS_FAILED);
            set_diagnostic(diagnostic_out, map_diagnostic.empty()
                                               ? "preprocessor physical line count overflow"
                                               : map_diagnostic);
            return NULL;
        }
        simplecpp::cleanup(filedata);

        char *out = dup_string(result);
        if (!out) {
            set_status(status_out, CBM_PREPROCESS_FAILED);
            set_diagnostic(diagnostic_out, "allocation failed while copying preprocessed source");
            return NULL;
        }
        if (primary_source_lines.size() > std::numeric_limits<size_t>::max() / sizeof(uint32_t)) {
            free(out);
            set_status(status_out, CBM_PREPROCESS_FAILED);
            set_diagnostic(diagnostic_out, "preprocessor expansion map size overflow");
            return NULL;
        }
        size_t map_bytes = primary_source_lines.size() * sizeof(uint32_t);
        uint32_t *line_map = static_cast<uint32_t *>(malloc(map_bytes));
        if (!line_map) {
            free(out);
            set_status(status_out, CBM_PREPROCESS_FAILED);
            set_diagnostic(diagnostic_out,
                           "allocation failed while copying preprocessor expansion map");
            return NULL;
        }
        memcpy(line_map, primary_source_lines.data(), map_bytes);
        *primary_source_lines_out = line_map;
        *expanded_line_count_out = primary_source_lines.size();
        set_status(status_out, CBM_PREPROCESS_OK);
        return out;
    } catch (const std::bad_alloc &) {
        set_status(status_out, CBM_PREPROCESS_FAILED);
        set_diagnostic_cstr(diagnostic_out,
                            "allocation failed while preprocessing the complete source");
        return NULL;
    } catch (const std::exception &e) {
        set_status(status_out, CBM_PREPROCESS_FAILED);
        char message[1024];
        const char *detail = e.what();
        if (detail && *detail)
            snprintf(message, sizeof(message), "simplecpp exception while preprocessing: %.900s",
                     detail);
        else
            snprintf(message, sizeof(message), "simplecpp exception while preprocessing");
        set_diagnostic_cstr(diagnostic_out, message);
        return NULL;
    } catch (...) {
        set_status(status_out, CBM_PREPROCESS_FAILED);
        set_diagnostic_cstr(diagnostic_out, "unknown simplecpp exception while preprocessing");
        return NULL;
    }
}

void cbm_preprocess_free(char *expanded) {
    free(expanded);
}

void cbm_preprocess_line_map_free(uint32_t *primary_source_lines) {
    free(primary_source_lines);
}

void cbm_preprocess_diagnostic_free(char *diagnostic) {
    free(diagnostic);
}

} // extern "C"
