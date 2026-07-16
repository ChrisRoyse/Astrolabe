// Unity build: include simplecpp implementation directly since CGo only
// compiles .cpp files from the immediate package directory, not subdirs.
#include "vendored/simplecpp/simplecpp.cpp"

#include "preprocessor.h"
#include "vendored/simplecpp/simplecpp.h"

#include <cstdlib>
#include <cstring>
#include <exception>
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

static bool is_name_char(char c) {
    unsigned char uc = static_cast<unsigned char>(c);
    return (uc >= 'a' && uc <= 'z') || (uc >= 'A' && uc <= 'Z') || (uc >= '0' && uc <= '9') ||
           uc == '_';
}

static bool matches_directive(const char *name, int len) {
    static const char *const directives[] = {
        "define", "if", "ifdef", "ifndef", "elif", NULL,
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
        return true;
    case simplecpp::Output::WARNING:
    case simplecpp::Output::MISSING_HEADER:
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

char* cbm_preprocess(
    const char* source, int source_len,
    const char* filename,
    const char** extra_defines,
    const char** include_paths,
    int cpp_mode,
    CBMPreprocessStatus *status_out,
    char **diagnostic_out
) {
    set_status(status_out, CBM_PREPROCESS_NO_DIRECTIVES);
    if (diagnostic_out)
        *diagnostic_out = NULL;

    if (!source || source_len <= 0)
        return NULL;

    if (!source_has_preprocessor_work(source, source_len))
        return NULL;

    try {
        simplecpp::DUI dui;
        if (extra_defines) {
            for (int i = 0; extra_defines[i]; i++)
                dui.defines.push_back(extra_defines[i]);
        }
        if (include_paths) {
            for (int i = 0; include_paths[i]; i++)
                dui.includePaths.push_back(include_paths[i]);
        }
        dui.std = cpp_mode ? "c++20" : "c11";

        simplecpp::OutputList outputs;
        std::vector<std::string> files;
        files.push_back(filename ? filename : "<input>");

        simplecpp::TokenList rawtokens(source, static_cast<std::size_t>(source_len), files,
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
        simplecpp::cleanup(filedata);

        char* out = dup_string(result);
        if (!out) {
            set_status(status_out, CBM_PREPROCESS_FAILED);
            set_diagnostic(diagnostic_out, "allocation failed while copying preprocessed source");
            return NULL;
        }
        set_status(status_out, CBM_PREPROCESS_OK);
        return out;
    } catch (const std::exception &e) {
        set_status(status_out, CBM_PREPROCESS_FAILED);
        std::string message = "simplecpp exception while preprocessing";
        if (e.what() && *e.what()) {
            message += ": ";
            message += e.what();
        }
        set_diagnostic(diagnostic_out, message);
        return NULL;
    } catch (...) {
        set_status(status_out, CBM_PREPROCESS_FAILED);
        set_diagnostic(diagnostic_out, "unknown simplecpp exception while preprocessing");
        return NULL;
    }
}

void cbm_preprocess_free(char* expanded) {
    free(expanded);
}

void cbm_preprocess_diagnostic_free(char* diagnostic) {
    free(diagnostic);
}

} // extern "C"
