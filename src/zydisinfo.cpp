#include <type_traits>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <moves.hpp>
#include <inttypes.h>
#include <registry.hpp>
#include <Zydis/Zydis.h>

constexpr bool ONLY_X86 = false;

#define WINDOW_NAME "Zydis Info"

#undef ZYAN_NULL
#define ZYAN_NULL nullptr

#define ZYAN_STRLEN strlen
#define ZYAN_MEMSET memset
#undef ZYAN_PRINTF

#define COLOR_TOKEN_DEFAULT SCOLOR_DEFAULT

#define COLOR_TOKEN_PREFIX SCOLOR_PREFIX // black
#define COLOR_TOKEN_MNEMONIC SCOLOR_INSN
#define COLOR_TOKEN_REG SCOLOR_REG
#define COLOR_TOKEN_ADDR SCOLOR_CREFTAIL
#define COLOR_TOKEN_DISP SCOLOR_ALTOP
#define COLOR_TOKEN_IMM SCOLOR_NUMBER

#define ZYAN_VT100SGR_FG_BRIGHT_BLACK SCOLOR_HIDNAME
#define ZYAN_VT100SGR_FG_BRIGHT_BLUE SCOLOR_LIBNAME
#define ZYAN_VT100SGR_FG_BRIGHT_CYAN SCOLOR_DCHAR
#define ZYAN_VT100SGR_FG_BRIGHT_GREEN SCOLOR_VOIDOP
#define ZYAN_VT100SGR_FG_BRIGHT_MAGENTA SCOLOR_IMPNAME
#define ZYAN_VT100SGR_FG_BRIGHT_RED SCOLOR_CREFTAIL
#define ZYAN_VT100SGR_FG_BRIGHT_YELLOW SCOLOR_DREFTAIL
#define ZYAN_VT100SGR_FG_CYAN SCOLOR_MACRO
#define ZYAN_VT100SGR_FG_WHITE SCOLOR_HIDNAME
#define ZYAN_VT100SGR_FG_YELLOW SCOLOR_SEGNAME
#define ZYAN_VT100SGR_FG_DEFAULT SCOLOR_DEFAULT

void decode_segments(ea_t ea, ZyanBool print_hints = ZYAN_TRUE);

struct ida_highlight_state_machine
{
  enum state_t
  {
    STATE_DEFAULT,
    STATE_SCOLOR_ON,
    STATE_SCOLOR_OFF
  };

  void reset()
  {
    state = STATE_DEFAULT;
  }

  bool operator()(char ch)
  {
    return is_newline(ch);
  }

  state_t state = STATE_DEFAULT;
  bool is_newline(char ch)
  {
    if (state == STATE_DEFAULT)
    {
      switch (ch)
      {
      case '\n':
        return true;
      case COLOR_ON:
        state = STATE_SCOLOR_ON;
        break;
      case COLOR_OFF:
        state = STATE_SCOLOR_OFF;
        break;
      }
      return false;
    }

    switch (state)
    {
    case STATE_SCOLOR_OFF:
    case STATE_SCOLOR_ON:
      if (ch > COLOR_LUMINA)
      {
        ::msg("Invalid color code: %d\n", ch);
      }
      state = STATE_DEFAULT;
      break;
    case STATE_DEFAULT:
      break;
    }
    return false;
  }
};

class logger_t
{
public:
  size_t log(const qstring &msg);

  void clear()
  {
    tmp_lines.clear();
    tmp_line.clear();
    state_machine.reset();
  }

  strvec_t &get_lines()
  {
    if (!tmp_line.empty())
    {
      tmp_lines.push_back().line.swap(tmp_line);
    }
    return tmp_lines;
  }

private:
  strvec_t tmp_lines;
  qstring tmp_line;
  ida_highlight_state_machine state_machine;
};

static logger_t logger;

size_t logger_t::log(const qstring &msg)
{
  for (auto ptr = msg.begin(), end = msg.end(); ptr < end;)
  {
    auto nl = std::find_if(ptr, end, state_machine);
    if (nl == end)
    {
      tmp_line.append(ptr);
      break;
    }
    tmp_line.append(ptr, nl - ptr);
    tmp_lines.push_back().line.swap(tmp_line);
    ptr = nl + 1;
  }

  return msg.length();
}

int ZYAN_PRINTF(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  qstring buf;
  auto message = buf.vsprnt(format, args);
  logger.log(message);
  va_end(args);
  return message.length();
}

#undef ZYAN_PUTS

#define ZYAN_PUTS(msg) logger.log(msg "\n")

#define CVT100_OUT(sequence) SCOLOR_ON sequence

//-------------------------------------------------------------------------

#define QUOTE(str) #str
#define EXPAND_AND_QUOTE(str) QUOTE(str)

#define SHOW_COLOR(CODE) COLSTR(#CODE, CODE) " " EXPAND_AND_QUOTE(CODE)

static struct
{
  const char *text;
  bgcolor_t color;
} const sample_text[] =
    {
        {"colors:", 0xFFFFFF},
        {SHOW_COLOR(COLOR_TOKEN_DEFAULT), 0xFFFFFF},
        {SHOW_COLOR(COLOR_TOKEN_PREFIX), 0xFFFFFF},
        {SHOW_COLOR(COLOR_TOKEN_MNEMONIC), 0xFFFFFF},
        {SHOW_COLOR(COLOR_TOKEN_REG), 0xFFFFFF},
        {SHOW_COLOR(COLOR_TOKEN_ADDR), 0xFFFFFF},
        {SHOW_COLOR(COLOR_TOKEN_DISP), 0xFFFFFF},
        {SHOW_COLOR(COLOR_TOKEN_IMM), 0xFFFFFF},
        {SHOW_COLOR(ZYAN_VT100SGR_FG_BRIGHT_BLACK), 0xFFFFFF},
        {SHOW_COLOR(ZYAN_VT100SGR_FG_BRIGHT_BLUE), 0xFFFFFF},
        {SHOW_COLOR(ZYAN_VT100SGR_FG_BRIGHT_CYAN), 0xFFFFFF},
        {SHOW_COLOR(ZYAN_VT100SGR_FG_BRIGHT_GREEN), 0xFFFFFF},
        {SHOW_COLOR(ZYAN_VT100SGR_FG_BRIGHT_MAGENTA), 0xFFFFFF},
        {SHOW_COLOR(ZYAN_VT100SGR_FG_BRIGHT_RED), 0xFFFFFF},
        {SHOW_COLOR(ZYAN_VT100SGR_FG_BRIGHT_YELLOW), 0xFFFFFF},
        {SHOW_COLOR(ZYAN_VT100SGR_FG_CYAN), 0xFFFFFF},
        {SHOW_COLOR(ZYAN_VT100SGR_FG_WHITE), 0xFFFFFF},
        {SHOW_COLOR(ZYAN_VT100SGR_FG_YELLOW), 0xFFFFFF},
        {SHOW_COLOR(ZYAN_VT100SGR_FG_DEFAULT), 0xFFFFFF},

        {"", 0xFFFFFF},
        {"list of all ida colors", 0xFFFFFF},

        {SHOW_COLOR(SCOLOR_ADDR) "///< Hidden address mark", 0xffffff},
        {SHOW_COLOR(SCOLOR_ALTOP) "///< Alternative operand", 0xffffff},
        {SHOW_COLOR(SCOLOR_ASMDIR) "///< Assembler directive", 0xffffff},
        {SHOW_COLOR(SCOLOR_AUTOCMT) "///< Automatic comment", 0xffffff},
        {SHOW_COLOR(SCOLOR_BINPREF) "///< Binary line prefix bytes", 0xffffff},
        {SHOW_COLOR(SCOLOR_CNAME) "///< Regular code name", 0xffffff},
        {SHOW_COLOR(SCOLOR_CODNAME) "///< Dummy code name", 0xffffff},
        {SHOW_COLOR(SCOLOR_COLLAPSED) "///< Collapsed line", 0xffffff},
        {SHOW_COLOR(SCOLOR_CREF) "///< Code reference", 0xffffff},
        {SHOW_COLOR(SCOLOR_CREFTAIL) "///< Code reference to tail byte", 0xffffff},
        {SHOW_COLOR(SCOLOR_DATNAME) "///< Dummy Data Name", 0xffffff},
        {SHOW_COLOR(SCOLOR_DEFAULT) "///< Default", 0xffffff},
        {SHOW_COLOR(SCOLOR_DEMNAME) "///< Demangled Name", 0xffffff},
        {SHOW_COLOR(SCOLOR_DCHAR) "///< Char constant in data directive", 0xffffff},
        {SHOW_COLOR(SCOLOR_DNAME) "///< Regular Data Name", 0xffffff},
        {SHOW_COLOR(SCOLOR_DNUM) "///< Numeric constant in data directive", 0xffffff},
        {SHOW_COLOR(SCOLOR_DREF) "///< Data reference", 0xffffff},
        {SHOW_COLOR(SCOLOR_DREFTAIL) "///< Data reference to tail byte", 0xffffff},
        {SHOW_COLOR(SCOLOR_DSTR) "///< String constant in data directive", 0xffffff},
        {SHOW_COLOR(SCOLOR_ERROR) "///< Error or problem", 0xffffff},
        {SHOW_COLOR(SCOLOR_EXTRA) "///< Extra line", 0xffffff},
        {SHOW_COLOR(SCOLOR_HIDNAME) "///< Hidden name", 0xffffff},
        {SHOW_COLOR(SCOLOR_CHAR) "///< Char constant in instruction", 0xffffff},
        {SHOW_COLOR(SCOLOR_IMPNAME) "///< Imported name", 0xffffff},
        {SHOW_COLOR(SCOLOR_INSN) "///< Instruction", 0xffffff},
        {SHOW_COLOR(SCOLOR_KEYWORD) "///< Keywords", 0xffffff},
        {SHOW_COLOR(SCOLOR_LIBNAME) "///< Library function name", 0xffffff},
        {SHOW_COLOR(SCOLOR_LOCNAME) "///< Local variable name", 0xffffff},
        {SHOW_COLOR(SCOLOR_MACRO) "///< Macro", 0xffffff},
        {SHOW_COLOR(SCOLOR_NUMBER) "///< Numeric constant in instruction", 0xffffff},
        {SHOW_COLOR(SCOLOR_PREFIX) "///< Line prefix", 0xffffff},
        {SHOW_COLOR(SCOLOR_REG) "///< Register name", 0xffffff},
        {SHOW_COLOR(SCOLOR_REGCMT) "///< Regular comment", 0xffffff},
        {SHOW_COLOR(SCOLOR_RPTCMT) "///< Repeatable comment (defined not here)", 0xffffff},
        {SHOW_COLOR(SCOLOR_SEGNAME) "///< Segment name", 0xffffff},
        {SHOW_COLOR(SCOLOR_STRING) "///< String constant in instruction", 0xffffff},
        {SHOW_COLOR(SCOLOR_SYMBOL) "///< Punctuation", 0xffffff},
        {SHOW_COLOR(SCOLOR_UNAME) "///< Regular unknown name", 0xffffff},
        {SHOW_COLOR(SCOLOR_UNKNAME) "///< Dummy unknown name", 0xffffff},
        {SHOW_COLOR(SCOLOR_VOIDOP) "///< Void operand", 0xffffff},

};

#if IDA_SDK_VERSION >= 920

struct zydis_prefix_t;

DECLARE_LISTENER(prefix_ui_listener_t, zydis_prefix_t, ctx);

struct zydis_prefix_t : public user_defined_prefix_t
{
  prefix_ui_listener_t ui_listener = prefix_ui_listener_t(*this);

  zydis_prefix_t(const void *owner) : user_defined_prefix_t(16, owner), ui_listener(prefix_ui_listener_t(*this))
  {
    hook_event_listener(HT_UI, &ui_listener, owner);
  }

  ~zydis_prefix_t()
  {
    unhook_event_listener(HT_UI, &ui_listener);
  }

  virtual void idaapi get_user_defined_prefix(
      qstring *out,
      ea_t ea,
      const insn_t &insn,
      int lnnum,
      int indent,
      const char *line) override
  {
    out->qclear(); // empty prefix by default

    if (indent != -1) // a directive
      return;

    if (line[0] == '\0') // empty line
      return;

    auto flags = get_flags(ea);
    if (!is_code(flags))
      return;

    if (insn.itype == 0)
    {
      // not an instruction
      return;
    }

    // calcrel

    // if (tag_advance(line, 1)[-1] == ash.cmnt[0]) // comment line...
    //   return;

    // We don't want the prefix to be printed again for other lines of the
    // same instruction/data. For that we remember the line number
    // and compare it before generating the prefix

    // if (pd->old_ea == ea && pd->old_lnnum == lnnum)
    //   return;

    // Ok, seems that we found an instruction line.

    // We don't bother about the width of the prefix
    // because it will be padded with spaces by the kernel

    logger.clear();
    decode_segments(ea, ZYAN_FALSE);

    // msg("zydis_prefix_t::get_user_defined_prefix: %llx lnnum: %d line: '%s'\n", ea, lnnum, line);

    out->append(" ", 1);
    auto lines = logger.get_lines();
    for (auto &line : lines)
    {
      out->append(line.line.c_str(), line.line.length());
    }
  }
};

size_t get_prefix_size(ea_t current_ea)
{
  // static size_t prefix_size = 0;
  // if (prefix_size > 0)
  //   return prefix_size;
  char tmp[50];
  return ea2str(tmp, sizeof(tmp), current_ea);
  // prefix_size = ea2str(tmp, sizeof(tmp), current_ea);
  // return prefix_size;
};

//--------------------------------------------------------------------------
ssize_t idaapi prefix_ui_listener_t::on_event(ssize_t code, va_list va)
{
  if (code != ui_get_custom_viewer_hint)
    return 0;

  ///< cb: ui wants to display a hint for a viewer (idaview or custom).
  ///< Every subscriber is supposed to append the hint lines
  ///< to HINT and increment IMPORTANT_LINES accordingly.
  ///< Completely overwriting the existing lines in HINT
  ///< is possible but not recommended.
  ///< If the REG_HINTS_MARKER sequence is found in the
  ///< returned hints string, it will be replaced with the
  ///< contents of the "regular" hints.
  ///< If the SRCDBG_HINTS_MARKER sequence is found in the
  ///< returned hints string, it will be replaced with the
  ///< contents of the source-level debugger-generated hints.
  ///< The following keywords might appear at the beginning of the
  ///< returned hints:
  ///< HIGHLIGHT text\n
  ///<   where text will be highlighted
  ///< CAPTION caption\n
  ///<   caption for the hint widget
  ///< \param[out] hint             (::qstring *) the output string,
  ///<                              on input contains hints from the previous subscribes
  ///< \param viewer                (TWidget*) viewer
  ///< \param place                 (::place_t *) current position in the viewer
  ///< \param[out] important_lines  (int *) number of important lines,
  ///<                                     should be incremented,
  ///<                                     if zero, the result is ignored
  ///< \retval 0 continue collecting hints with other subscribers
  ///< \retval 1 stop collecting hints
  qstring &hint = *va_arg(va, qstring *);
  TWidget *viewer = va_arg(va, TWidget *);
  place_t *place = va_arg(va, place_t *);
  int *important_lines = va_arg(va, int *);

  if (place == nullptr)
    return 0;
  if (get_widget_type(viewer) != BWN_DISASM) // only show hint for disassembly viewer
    return 0;

  // msg("plugin_ctx_t::on_event: got hint request for unknown viewer %p\n", viewer);
  if (place == nullptr)
    return 0;
  // idaplace_t *idaplace = (idaplace_t *)place;

  auto current_ea = place->toea();

  if (current_ea == BADADDR)
    return 0;

  if (!is_code(get_flags(current_ea)))
    return 0;

  listing_location_t current_location{};
  auto ok = get_custom_viewer_location(&current_location, viewer, true);
  if (!ok)
    return 0;

  auto &loc = *current_location.loc;
  auto &pos = loc.rinfo.pos;

  // msg("text %p\n", current_location.text);
  // msg("text: %s\n", current_location.text->c_str());

  // hint.cat_sprnt("placeea %p line num: %d x: %d y: %d valid: %d text: %s\n", place->toea(), place->lnnum, pos.cx, pos.cy, loc.is_valid(), current_location.text->c_str());

  // auto text_copy = *current_location.text;

  auto prefix_size = get_prefix_size(current_ea);
  if (prefix_size <= 0)
    return 0;

  auto item_size = get_item_size(current_ea);

  prefix_size += 1;
  // don't show hint if mouse is not over it
  if (pos.cx < prefix_size)
    return 0;
  auto hex_bytes_size = item_size * 3 - 2;
  auto prefix_end = hex_bytes_size + prefix_size;
  if (pos.cx > prefix_end)
    return 0;

  logger.clear();
  decode_segments(current_ea);

  for (auto &&line : logger.get_lines())
  {
    hint.append(line.line.c_str(), line.line.length());
    hint.append("\n");
    *important_lines += 1;
  }
  return 0;
}

#endif

//-------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t, public event_listener_t
{
  TWidget *widget = nullptr;
  strvec_t lines;
  ea_t current_ea = BADADDR;

#if IDA_SDK_VERSION >= 920
  zydis_prefix_t *prefix = nullptr;
  void show_prefix(bool show)
  {
    if (show)
    {
      if (prefix == nullptr)
        prefix = new zydis_prefix_t(this);
    }
    else
    {
      delete prefix;
      prefix = nullptr;
    }
  }
#endif

  plugin_ctx_t();
  virtual bool idaapi run(size_t) override;
  void show_demo();
  virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;
  void decode_at_current_ea();
};

#if IDA_SDK_VERSION >= 920

enum prefix_visibility_t
{
  PREFIX_UNDEFINED = 0,
  PREFIX_SHOW = 1,
  PREFIX_HIDE = 2
};

struct prefix_config_t
{
  constexpr static const char *REG_SUBKEY = "show_prefix";
  constexpr static const char *REG_SECTION = "zydisinfo";
  constexpr static const char *NETNODE_NAME = "$ zydisinfo";

  // per idb setting,
  // 0 = undefined, 1 = show, 2 = hide
  prefix_visibility_t show_in_idb = PREFIX_UNDEFINED;
  // global setting, default is false
  prefix_visibility_t show_in_all_idbs = PREFIX_UNDEFINED;

  prefix_config_t()
  {
    read();
  }

  bool show() const
  {
    if (show_in_idb != PREFIX_UNDEFINED)
      return show_in_idb == PREFIX_SHOW;
    if (show_in_all_idbs != PREFIX_UNDEFINED)
      return show_in_all_idbs == PREFIX_SHOW;
    return false;
  }

  void save()
  {
    netnode n(NETNODE_NAME, 0, true);
    switch (show_in_idb)
    {
    case PREFIX_SHOW:
      n.set_long(1);
      break;
    case PREFIX_HIDE:
      n.set_long(0);
      break;
    case PREFIX_UNDEFINED:
      n.kill();
      break;
    }

    if (show_in_all_idbs != PREFIX_UNDEFINED)
    {
      bool global_show = show_in_all_idbs == PREFIX_SHOW;
      reg_write_bool(REG_SECTION, global_show, REG_SUBKEY);
    }
    else
    {
      reg_delete(REG_SECTION, REG_SUBKEY);
    }
  }

  void read()
  {
    if (reg_exists(REG_SECTION, REG_SUBKEY))
    {
      // load global setting
      bool global_show = reg_read_bool(REG_SECTION, false, REG_SUBKEY);
      show_in_all_idbs = global_show ? PREFIX_SHOW : PREFIX_HIDE;
    }
    else
    {
      show_in_all_idbs = PREFIX_UNDEFINED;
    }

    // load per idb setting
    netnode n(NETNODE_NAME, 0, true);
    auto val = n.long_value();
    switch (val)
    {
    case 1:
      show_in_idb = PREFIX_SHOW;
      break;
    case 0:
      show_in_idb = PREFIX_HIDE;
      break;
    default:
      show_in_idb = PREFIX_UNDEFINED;
      break;
    }
  }
};

struct configure_action_t : public action_handler_t
{
  plugin_ctx_t *plugin;
  configure_action_t(plugin_ctx_t *p) : action_handler_t(), plugin(p) {}

  virtual int idaapi activate(action_activation_ctx_t *ctx) override
  {
    ushort flags = 0;

    /*
| global defined | global value | local defined | local value | result |
| -------------- | ------------ | ------------- | ----------- | ------ |
| _              | _            | True          | True        | True   |
| _              | _            | True          | False       | False  |
| True           | True         | False         | _           | True   |
| True           | False        | False         | _           | False  |

(global && global_def && !local_def) || (local && local_def)
    */
    const char *form = R"(HELP
This dialog allows to configure when to show the instruction prefix generated by the Zydis Info plugin.

If both options are defined, the per-idb option has precedence over the global option.
If neither option is enabled, the prefix will not be shown.

Changes to the global option will only affect new IDBs.
ENDHELP
Zydis Info configuration


<#Prefixes in this idb#Show prefixes in ~t~his idb:C>
<#Prefixes in all idbs#Show prefixes in ~a~ll idbs:C>>

)";

    CASSERT(sizeof(flags) == sizeof(ushort));

    prefix_config_t config;

    if (config.show_in_idb == PREFIX_SHOW)
      flags |= 1;
    if (config.show_in_all_idbs == PREFIX_SHOW)
      flags |= 2;

    if (1 == ask_form(form, &flags))
    {
      config.show_in_idb = (flags & 1) ? PREFIX_SHOW : PREFIX_HIDE;
      config.show_in_all_idbs = (flags & 2) ? PREFIX_SHOW : PREFIX_HIDE;
      config.save();
      plugin->show_prefix(config.show());
    }
    return 1;
  }
  virtual action_state_t idaapi update(action_update_ctx_t *ctx) override
  {
    return AST_ENABLE_ALWAYS;
  }
};
#endif

//---------------------------------------------------------------------------
// Keyboard callback
static bool idaapi ct_keyboard(TWidget * /*v*/, int key, int shift, void *ud)
{
  if (shift != 0)
    return false;

  plugin_ctx_t *plugin = (plugin_ctx_t *)ud;
  switch (key)
  {
  case 'N':
    // warning("The hotkey 'N' has been pressed");
    plugin->show_demo();

    return true;
  case IK_ESCAPE:
    close_widget(plugin->widget, WCLS_SAVE | WCLS_CLOSE_LATER);
    return true;
  }
  return false;
}

//---------------------------------------------------------------------------
// This callback will be called each time the keyboard cursor position
// is changed
static void idaapi ct_curpos(TWidget *v, void *)
{
  qstring line;

  uint32 flags = 0;
  if (!get_highlight(&line, v, &flags, HIF_SLOT_0))
  {
    return;
  }
  auto ida_view = find_widget("IDA View-A");
  if (!ida_view)
  {
    return;
  }
  set_highlight(ida_view, line.c_str(), flags);
}

//-------------------------------------------------------------------------
plugin_ctx_t::plugin_ctx_t()
{
// intel x86 processor and ida >= 9.2
#if IDA_SDK_VERSION >= 920

  if (PH.id == PLFM_386)
  {
    prefix_config_t config;
    show_prefix(config.show());

    static const action_desc_t action_desc = ACTION_DESC_LITERAL_PLUGMOD(
        "zydisinfo:configure",         // The action name. This is how the action will be identified in the system
        "Zydis Info...",        // The action text. This text will be displayed in menus and toolbars.
        new configure_action_t(this),  // The action handler.
        this,                          // plgmod_t *plugin
        nullptr,                       // Optional: the action shortcut (nullptr if none)
        "Configure Zydis Info plugin", // Optional: the action tooltip (nullptr if none)
        0);                            // Optional: the action icon (0 if none)
    register_action(action_desc);

    attach_action_to_menu(
        "Options", "zydisinfo:configure", SETMENU_APP);
  }

#endif
}

bool get_auto_comment(qstring *buf, ea_t ea)
{
  insn_t insn;
  if (!decode_insn(&insn, ea))
    return false;
  if (get_predef_insn_cmt(buf, insn) == -1)
    return false;
  return !buf->empty();
}

//---------------------------------------------------------------------------

/* ============================================================================================== */
/* Colors                                                                                         */
/* ============================================================================================== */

/* ---------------------------------------------------------------------------------------------- */
/* Configuration                                                                                  */
/* ---------------------------------------------------------------------------------------------- */

#define COLOR_HEADER ZYAN_VT100SGR_FG_DEFAULT
#define COLOR_HEADER_TITLE ZYAN_VT100SGR_FG_CYAN
#define COLOR_VALUE_LABEL ZYAN_VT100SGR_FG_DEFAULT
#define COLOR_VALUE_R ZYAN_VT100SGR_FG_BRIGHT_RED
#define COLOR_VALUE_G ZYAN_VT100SGR_FG_BRIGHT_GREEN
#define COLOR_VALUE_B ZYAN_VT100SGR_FG_BRIGHT_BLUE

/* ---------------------------------------------------------------------------------------------- */

/* ============================================================================================== */
/* Helper functions                                                                               */
/* ============================================================================================== */

/* ---------------------------------------------------------------------------------------------- */
/* General                                                                                        */
/* ---------------------------------------------------------------------------------------------- */

/**
 * Returns the action string for a specific CPU/FPU flag.
 *
 * @param accessed_flags    A pointer to the `ZydisAccessedFlags` struct.
 * @param flag              The number of the flag.
 *
 * @return The action string for the requested flag, or `ZYAN_NULL`.
 */
static const char *GetAccessedFlagActionString(const ZydisAccessedFlags *accessed_flags,
                                               ZyanU8 flag)
{
  ZYAN_ASSERT(flag < 32);

  const char *result = nullptr;

  if (accessed_flags->tested & (1 << flag))
  {
    result = "T";
  }
  if (accessed_flags->modified & (1 << flag))
  {
    result = (result == nullptr) ? "M" : "T_M";
    return result;
  }

  if (accessed_flags->set_0 & (1 << flag))
  {
    return "0";
  }
  if (accessed_flags->set_1 & (1 << flag))
  {
    return "1";
  }
  if (accessed_flags->undefined & (1 << flag))
  {
    return "U";
  }

  return result;
}

/* ---------------------------------------------------------------------------------------------- */
/* Text output                                                                                    */
/* ---------------------------------------------------------------------------------------------- */

const char *FormatZyanStatus(ZyanStatus status)
{
  static const char *strings_zycore[] =
      {
          /* 00 */ "SUCCESS",
          /* 01 */ "FAILED",
          /* 02 */ "TRUE",
          /* 03 */ "FALSE",
          /* 04 */ "INVALID_ARGUMENT",
          /* 05 */ "INVALID_OPERATION",
          /* 06 */ "NOT_FOUND",
          /* 07 */ "OUT_OF_RANGE",
          /* 08 */ "INSUFFICIENT_BUFFER_SIZE",
          /* 09 */ "NOT_ENOUGH_MEMORY",
          /* 0A */ "NOT_ENOUGH_MEMORY",
          /* 0B */ "BAD_SYSTEMCALL"};
  static const char *strings_zydis[] =
      {
          /* 00 */ "NO_MORE_DATA",
          /* 01 */ "DECODING_ERROR",
          /* 02 */ "INSTRUCTION_TOO_LONG",
          /* 03 */ "BAD_REGISTER",
          /* 04 */ "ILLEGAL_LOCK",
          /* 05 */ "ILLEGAL_LEGACY_PFX",
          /* 06 */ "ILLEGAL_REX",
          /* 07 */ "INVALID_MAP",
          /* 08 */ "MALFORMED_EVEX",
          /* 09 */ "MALFORMED_MVEX",
          /* 0A */ "INVALID_MASK",
          /* 0B */ "SKIP_TOKEN",
          /* 0C */ "IMPOSSIBLE_INSTRUCTION"};

  if (ZYAN_STATUS_MODULE(status) == ZYAN_MODULE_ZYCORE)
  {
    status = ZYAN_STATUS_CODE(status);
    ZYAN_ASSERT(status < ZYAN_ARRAY_LENGTH(strings_zycore));
    return strings_zycore[status];
  }

  if (ZYAN_STATUS_MODULE(status) == ZYAN_MODULE_ZYDIS)
  {
    status = ZYAN_STATUS_CODE(status);
    ZYAN_ASSERT(status < ZYAN_ARRAY_LENGTH(strings_zydis));
    return strings_zydis[status];
  }

  ZYAN_UNREACHABLE;
}

void PrintStatusError(ZyanStatus status, const char *message)
{
  ZYAN_ASSERT(ZYAN_FAILED(status));

  if (ZYAN_STATUS_MODULE(status) >= ZYAN_MODULE_USER)
  {
    ZYAN_PRINTF(COLSTR("%s", SCOLOR_ERROR) ": User defined status code [0x%" PRIx32 "]\n", message, status);
  }
  else
  {
    ZYAN_PRINTF(COLSTR("%s", SCOLOR_ERROR) ": %s [0x%" PRIx32 "]\n", message, FormatZyanStatus(status), status);
  }
}

/**
 * Prints a section header.
 *
 * @param   name    The section name.
 */
static void PrintSectionHeader(const char *name)
{
  ZYAN_ASSERT(ZYAN_STRLEN(name) <= 8);
  ZYAN_PRINTF("%s== [ %s%8s%s ] =============================================================="
              "==============================%s\n",
              CVT100_OUT(COLOR_HEADER), CVT100_OUT(COLOR_HEADER_TITLE), name, CVT100_OUT(COLOR_HEADER),
              CVT100_OUT(SCOLOR_DEFAULT));
}

/**
 * Prints a value label.
 *
 * @param   name    The value name.
 */
static void PrintValueLabel(const char *name)
{
  ZYAN_ASSERT(ZYAN_STRLEN(name) <= 11);
  ZYAN_PRINTF("%s%11s:%s ", CVT100_OUT(COLOR_VALUE_LABEL), name, CVT100_OUT(SCOLOR_DEFAULT));
}

/**
 * Prints a formatted value using red color.
 *
 * @param   name    The value name.
 * @param   format  The format string.
 * @param   ...     The format arguments.
 */

#define PRINT_VALUE_R(name, format, ...)                                  \
  PrintValueLabel(name);                                                  \
  ZYAN_PRINTF("%s" format "%s\n", CVT100_OUT(COLOR_VALUE_R), __VA_ARGS__, \
              CVT100_OUT(SCOLOR_DEFAULT));

/**
 * Prints a formatted value using green color.
 *
 * @param   name    The value name.
 * @param   format  The format string.
 * @param   ...     The format arguments.
 */
#define PRINT_VALUE_G(name, format, ...)                                  \
  PrintValueLabel(name);                                                  \
  ZYAN_PRINTF("%s" format "%s\n", CVT100_OUT(COLOR_VALUE_G), __VA_ARGS__, \
              CVT100_OUT(SCOLOR_DEFAULT));

/**
 * Prints a formatted value using blue color.
 *
 * @param   name    The value name.
 * @param   format  The format string.
 * @param   ...     The format arguments.
 */
#define PRINT_VALUE_B(name, format, ...)                                  \
  PrintValueLabel(name);                                                  \
  ZYAN_PRINTF("%s" format "%s\n", CVT100_OUT(COLOR_VALUE_B), __VA_ARGS__, \
              CVT100_OUT(SCOLOR_DEFAULT));

/* ---------------------------------------------------------------------------------------------- */

/* ============================================================================================== */
/* Print functions                                                                                */
/* ============================================================================================== */

#if !defined(ZYDIS_DISABLE_SEGMENT)

/**
 * Prints instruction segments (parts).
 *
 * @param   instruction A pointer to the `ZydisDecodedInstruction` struct.
 * @param   buffer      The buffer that contains the instruction bytes.
 * @param   print_hints Controls the printing of descriptive hints.
 */
static void PrintSegments(const ZydisDecodedInstruction *instruction, const ZyanU8 *buffer,
                          ZyanBool print_hints)
{
  ZydisInstructionSegments segments;
  ZydisGetInstructionSegments(instruction, &segments);

  struct
  {
    ZyanU8 pos;
    const char *color;
    const char *name;
  } print_info[ZYAN_ARRAY_LENGTH(segments.segments)];

  ZyanU8 pos = 0;
  ZyanU8 imm = 0;
  for (ZyanU8 i = 0; i < segments.count; ++i)
  {
    print_info[i].pos = pos;

    switch (segments.segments[i].type)
    {
    case ZYDIS_INSTR_SEGMENT_PREFIXES:
      print_info[i].color = CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_RED);
      print_info[i].name = "PREFIXES";
      break;
    case ZYDIS_INSTR_SEGMENT_REX:
      print_info[i].color = CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_MAGENTA);
      print_info[i].name = "REX";
      break;
    case ZYDIS_INSTR_SEGMENT_XOP:
      print_info[i].color = CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_MAGENTA);
      print_info[i].name = "XOP";
      break;
    case ZYDIS_INSTR_SEGMENT_VEX:
      print_info[i].color = CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_MAGENTA);
      print_info[i].name = "VEX";
      break;
    case ZYDIS_INSTR_SEGMENT_EVEX:
      print_info[i].color = CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_MAGENTA);
      print_info[i].name = "EVEX";
      break;
    case ZYDIS_INSTR_SEGMENT_MVEX:
      print_info[i].color = CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_MAGENTA);
      print_info[i].name = "MVEX";
      break;
    case ZYDIS_INSTR_SEGMENT_OPCODE:
      print_info[i].color = CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_BLUE);
      print_info[i].name = "OPCODE";
      break;
    case ZYDIS_INSTR_SEGMENT_MODRM:
      print_info[i].color = CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_CYAN);
      print_info[i].name = "MODRM";
      break;
    case ZYDIS_INSTR_SEGMENT_SIB:
      print_info[i].color = CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_GREEN);
      print_info[i].name = "SIB";
      break;
    case ZYDIS_INSTR_SEGMENT_DISPLACEMENT:
      print_info[i].color = CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_YELLOW);
      print_info[i].name = "DISP";
      break;
    case ZYDIS_INSTR_SEGMENT_IMMEDIATE:
      if (imm == 0)
      {
        print_info[i].color = CVT100_OUT(ZYAN_VT100SGR_FG_YELLOW);
        imm = 1;
      }
      else
      {
        print_info[i].color = CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_YELLOW);
      }
      print_info[i].name = "IMM";
      break;
    default:
      ZYAN_UNREACHABLE;
    }

    ZYAN_PRINTF("%s", print_info[i].color);
    for (int j = 0; j < segments.segments[i].size; ++j)
    {
      if (segments.segments[i].type == ZYDIS_INSTR_SEGMENT_PREFIXES)
      {
        ZYAN_ASSERT(segments.segments[i].size <= instruction->raw.prefix_count);
        switch (instruction->raw.prefixes[j].type)
        {
        case ZYDIS_PREFIX_TYPE_IGNORED:
          ZYAN_PRINTF("%s%02X%s ", CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_BLACK),
                      buffer[segments.segments[i].offset + j], print_info[i].color);
          pos += 3;
          break;
        case ZYDIS_PREFIX_TYPE_EFFECTIVE:
          pos += (ZyanU8)ZYAN_PRINTF("%02X ", buffer[segments.segments[i].offset + j]);
          break;
        case ZYDIS_PREFIX_TYPE_MANDATORY:
          ZYAN_PRINTF("%s%02X%s ",
                      CVT100_OUT(ZYAN_VT100SGR_FG_CYAN),
                      buffer[segments.segments[i].offset + j], print_info[i].color);
          pos += 3;
          break;
        default:
          ZYAN_UNREACHABLE;
        }
      }
      else
      {
        pos += (ZyanU8)ZYAN_PRINTF("%02X ", buffer[segments.segments[i].offset + j]);
      }
    }
  }
  ZYAN_PRINTF("%s\n", CVT100_OUT(SCOLOR_DEFAULT));

  if (!print_hints)
  {
    return;
  }

  for (ZyanU8 i = 0; i < segments.count; ++i)
  {
    ZyanU8 j = 0;
    ZyanU8 k = 0;
    while (j <= print_info[segments.count - i - 1].pos)
    {
      if (j == print_info[k].pos)
      {
        ZYAN_PRINTF("%s:", print_info[k].color);
        ++k;
      }
      else
      {
        ZYAN_PRINTF(" ");
      }
      ++j;
    }
    ZYAN_PRINTF("..%s%s\n", print_info[segments.count - i - 1].color,
                print_info[segments.count - i - 1].name);
  }

  ZYAN_PRINTF(CVT100_OUT(SCOLOR_DEFAULT));
}

#endif

#if !defined(ZYDIS_DISABLE_ENCODER)

/**
 * Prints a size optimized form of the input instruction.
 *
 * @param decoder       A pointer to the `ZydisDecoder` instance.
 * @param instruction   A pointer to the `ZydisDecodedInstruction` struct.
 * @param operands      A pointer to the `operands` array.
 * @param operand_count The length of the `operands` array.
 */
static void PrintSizeOptimizedForm(const ZydisDecoder *decoder,
                                   const ZydisDecodedInstruction *instruction, const ZydisDecodedOperand *operands,
                                   ZyanU8 operand_count)
{
  ZydisEncoderRequest request;
  ZyanStatus status = ZydisEncoderDecodedInstructionToEncoderRequest(instruction, operands,
                                                                     operand_count, &request);
  if (!ZYAN_SUCCESS(status))
  {
    PrintStatusError(status, "Failed to craft encoder request");
    return;
  }

  ZyanU8 data[ZYDIS_MAX_INSTRUCTION_LENGTH];
  ZyanUSize len = sizeof(data);
  status = ZydisEncoderEncodeInstruction(&request, data, &len);
  if (!ZYAN_SUCCESS(status))
  {
    PrintStatusError(status, "Could not encode instruction");
    return;
  }

  ZydisDecodedInstruction new_instruction;
  status = ZydisDecoderDecodeInstruction(decoder, ZYAN_NULL, &data, len, &new_instruction);
  if (!ZYAN_SUCCESS(status))
  {
    PrintStatusError(status, "Could not decode instruction");
    return;
  }

  // #if !defined(ZYDIS_DISABLE_SEGMENT)
  PrintSegments(&new_instruction, &data[0], ZYAN_FALSE);
  // #endif
}

#endif

/**
 * Prints instruction operands info.
 *
 * @param   instruction A pointer to the `ZydisDecodedInstruction` struct.
 * @param   operands    A pointer to the first `ZydisDecodedOperand` struct of the instruction.
 */
static void PrintOperands(const ZydisDecodedInstruction *instruction,
                          const ZydisDecodedOperand *operands)
{
  PrintSectionHeader("OPERANDS");
  ZYAN_PRINTF("%s##       TYPE  VISIBILITY  ACTION      ENCODING   SIZE  NELEM  ELEMSZ  ELEMTY"
              "PE                        VALUE%s\n",
              CVT100_OUT(COLOR_HEADER), CVT100_OUT(SCOLOR_DEFAULT));
  ZYAN_PRINTF("%s--  ---------  ----------  ------  ------------   ----  -----  ------  ------"
              "--  ---------------------------%s\n",
              CVT100_OUT(COLOR_HEADER), CVT100_OUT(SCOLOR_DEFAULT));

  ZyanU8 imm_id = 0;
  for (ZyanU8 i = 0; i < instruction->operand_count; ++i)
  {
    static const char *strings_operand_type[] =
        {
            "UNUSED",
            "REGISTER",
            "MEMORY",
            "POINTER",
            "IMMEDIATE"};
    ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(strings_operand_type) == ZYDIS_OPERAND_TYPE_MAX_VALUE + 1);

    static const char *strings_operand_visibility[] =
        {
            "INVALID",
            "EXPLICIT",
            "IMPLICIT",
            "HIDDEN"};
    ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(strings_operand_visibility) == ZYDIS_OPERAND_VISIBILITY_MAX_VALUE + 1);

    static const char *strings_operand_actions[] =
        {
            "NONE", // 0 0 0 0
            "R",    // 0 0 0 1
            "W",    // 0 0 1 0
            "RW",   // 0 0 1 1
            "CR",   // 0 1 0 0
            "-",    // 0 1 0 1
            "CRW",  // 0 1 1 0
            "-",    // 0 1 1 1
            "CW",   // 1 0 0 0
            "RCW",  // 1 0 0 1
            "-",    // 1 0 1 0
            "-",    // 1 0 1 1
            "CRCW", // 1 1 0 0
            "-",    // 1 1 0 1
            "-"     // 1 1 1 1
        };

    static const char *strings_element_type[] =
        {
            "INVALID",
            "STRUCT",
            "UINT",
            "INT",
            "FLOAT16",
            "FLOAT32",
            "FLOAT64",
            "FLOAT80",
            "BFLOAT16",
            "LONGBCD",
            "CC"};
    ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(strings_element_type) == ZYDIS_ELEMENT_TYPE_MAX_VALUE + 1);

    static const char *strings_operand_encoding[] =
        {
            "NONE",
            "MODRM_REG",
            "MODRM_RM",
            "OPCODE",
            "NDSNDD",
            "IS4",
            "MASK",
            "DISP8",
            "DISP16",
            "DISP32",
            "DISP64",
            "DISP16_32_64",
            "DISP32_32_64",
            "DISP16_32_32",
            "UIMM8",
            "UIMM16",
            "UIMM32",
            "UIMM64",
            "UIMM16_32_64",
            "UIMM32_32_64",
            "UIMM16_32_32",
            "SIMM8",
            "SIMM16",
            "SIMM32",
            "SIMM64",
            "SIMM16_32_64",
            "SIMM32_32_64",
            "SIMM16_32_32",
            "JIMM8",
            "JIMM16",
            "JIMM32",
            "JIMM64",
            "JIMM16_32_64",
            "JIMM32_32_64",
            "JIMM16_32_32"};
    ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(strings_operand_encoding) == ZYDIS_OPERAND_ENCODING_MAX_VALUE + 1);

    static const char *strings_memop_type[] =
        {
            "INVALID",
            "MEM",
            "AGEN",
            "MIB",
            "VSIB"};
    ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(strings_memop_type) == ZYDIS_MEMOP_TYPE_MAX_VALUE + 1);

    ZYAN_PRINTF("%s%2d  %s%9s  %10s  %6s  %12s  %s%5d   %4d  %6d  %s%8s%s",
                CVT100_OUT(COLOR_VALUE_G),
                i,
                CVT100_OUT(COLOR_VALUE_B),
                strings_operand_type[operands[i].type],
                strings_operand_visibility[operands[i].visibility],
                strings_operand_actions[operands[i].actions],
                strings_operand_encoding[operands[i].encoding],
                CVT100_OUT(COLOR_VALUE_G),
                operands[i].size,
                operands[i].element_count,
                operands[i].element_size,
                CVT100_OUT(COLOR_VALUE_B),
                strings_element_type[operands[i].element_type],
                CVT100_OUT(SCOLOR_DEFAULT));
    switch (operands[i].type)
    {
    case ZYDIS_OPERAND_TYPE_REGISTER:
      ZYAN_PRINTF("  %s%27s%s", CVT100_OUT(COLOR_VALUE_R),
                  ZydisRegisterGetString(operands[i].reg.value),
                  CVT100_OUT(SCOLOR_DEFAULT));
      break;
    case ZYDIS_OPERAND_TYPE_MEMORY:
      ZYAN_PRINTF("  %sTYPE  =%s%20s%s\n", CVT100_OUT(COLOR_VALUE_LABEL),
                  CVT100_OUT(COLOR_VALUE_B), strings_memop_type[operands[i].mem.type],
                  CVT100_OUT(SCOLOR_DEFAULT));
      ZYAN_PRINTF("  %s%84s =%s%20s%s\n",
                  CVT100_OUT(COLOR_VALUE_LABEL), "SEG  ", CVT100_OUT(COLOR_VALUE_R),
                  ZydisRegisterGetString(operands[i].mem.segment),
                  CVT100_OUT(SCOLOR_DEFAULT));

      ZYAN_PRINTF("  %s%84s =%s%20s%s\n",
                  CVT100_OUT(COLOR_VALUE_LABEL), "BASE ", CVT100_OUT(COLOR_VALUE_R),
                  ZydisRegisterGetString(operands[i].mem.base),
                  CVT100_OUT(SCOLOR_DEFAULT));

      if (operands[i].mem.index != 0)
        ZYAN_PRINTF("  %s%84s =%s%20s%s\n",
                    CVT100_OUT(COLOR_VALUE_LABEL), "INDEX", CVT100_OUT(COLOR_VALUE_R),
                    ZydisRegisterGetString(operands[i].mem.index),
                    CVT100_OUT(SCOLOR_DEFAULT));
      if (operands[i].mem.scale != 0)
        ZYAN_PRINTF("  %s%84s =%s%20d%s\n",
                    CVT100_OUT(COLOR_VALUE_LABEL), "SCALE", CVT100_OUT(COLOR_VALUE_G),
                    operands[i].mem.scale,
                    CVT100_OUT(SCOLOR_DEFAULT));
      if (operands[i].mem.disp.value != 0)
        ZYAN_PRINTF("  %s%84s =  %s0x%016" PRIX64 "%s",
                    CVT100_OUT(COLOR_VALUE_LABEL), "DISP ", CVT100_OUT(COLOR_VALUE_G),
                    operands[i].mem.disp.value,
                    CVT100_OUT(SCOLOR_DEFAULT));
      break;
    case ZYDIS_OPERAND_TYPE_POINTER:
      ZYAN_PRINTF("  %sSEG   =              %s0x%04" PRIX16 "%s\n",
                  CVT100_OUT(COLOR_VALUE_LABEL), CVT100_OUT(COLOR_VALUE_G),
                  operands[i].ptr.segment,
                  CVT100_OUT(SCOLOR_DEFAULT));
      ZYAN_PRINTF("  %s%84s =          %s0x%08" PRIX32 "%s",
                  CVT100_OUT(COLOR_VALUE_LABEL), "OFF  ", CVT100_OUT(COLOR_VALUE_G),
                  operands[i].ptr.offset,
                  CVT100_OUT(SCOLOR_DEFAULT));
      break;
    case ZYDIS_OPERAND_TYPE_IMMEDIATE:
      if (operands[i].imm.is_signed)
      {
        ZYAN_PRINTF("  %s[%s%s %s %s%2d%s] %s0x%016" PRIX64 "%s",
                    CVT100_OUT(COLOR_VALUE_LABEL),
                    CVT100_OUT(COLOR_VALUE_B),
                    operands[i].imm.is_signed ? "S" : "U",
                    operands[i].imm.is_relative ? "R" : "A",
                    CVT100_OUT(COLOR_VALUE_G),
                    instruction->raw.imm[imm_id].size,
                    CVT100_OUT(COLOR_VALUE_LABEL),
                    CVT100_OUT(COLOR_VALUE_G),
                    operands[i].imm.value.s,
                    CVT100_OUT(SCOLOR_DEFAULT));
      }
      else
      {
        ZYAN_PRINTF("  %s[%s%s %s %s%2d%s] %s0x%016" PRIX64 "%s",
                    CVT100_OUT(COLOR_VALUE_LABEL),
                    CVT100_OUT(COLOR_VALUE_B),
                    operands[i].imm.is_signed ? "S" : "U",
                    operands[i].imm.is_relative ? "R" : "A",
                    CVT100_OUT(COLOR_VALUE_G),
                    instruction->raw.imm[imm_id].size,
                    CVT100_OUT(COLOR_VALUE_LABEL),
                    CVT100_OUT(COLOR_VALUE_G),
                    operands[i].imm.value.u,
                    CVT100_OUT(SCOLOR_DEFAULT));
      }
      ++imm_id;
      break;
    default:
      ZYAN_UNREACHABLE;
    }
    ZYAN_PUTS("");
  }

  ZYAN_PRINTF("%s--  ---------  ----------  ------  ------------   ----  -----  ------  ------"
              "--  ---------------------------%s\n",
              CVT100_OUT(COLOR_HEADER), CVT100_OUT(SCOLOR_DEFAULT));
}

/**
 * Prints instruction flags info.
 *
 * @param   instruction A pointer to the `ZydisDecodedInstruction` struct.
 */
static void PrintFlags(const ZydisDecodedInstruction *instruction)
{
  static const char *strings_cpu_flags[] =
      {
          "CF",
          ZYAN_NULL,
          "PF",
          ZYAN_NULL,
          "AF",
          ZYAN_NULL,
          "ZF",
          "SF",
          "TF",
          "IF",
          "DF",
          "OF",
          "IOPL",
          ZYAN_NULL,
          "NT",
          ZYAN_NULL,
          "RF",
          "VM",
          "AC",
          "VIF",
          "VIP",
          "ID",
      };

  static const char *strings_fpu_flags[] =
      {
          "C0",
          "C1",
          "C2",
          "C3",
      };

  typedef struct FlagInfo_
  {
    const char *name;
    const char *action;
  } FlagInfo;

  FlagInfo flags[ZYAN_ARRAY_LENGTH(strings_cpu_flags) + ZYAN_ARRAY_LENGTH(strings_fpu_flags)];
  ZYAN_MEMSET(flags, 0, sizeof(flags));

  // CPU
  for (ZyanUSize i = 0; i < ZYAN_ARRAY_LENGTH(strings_cpu_flags); ++i)
  {
    flags[i].name = strings_cpu_flags[i];
    flags[i].action = GetAccessedFlagActionString(instruction->cpu_flags, (ZyanU8)i);
  }

  // FPU
  const ZyanUSize offset = ZYAN_ARRAY_LENGTH(strings_cpu_flags);
  for (ZyanUSize i = 0; i < ZYAN_ARRAY_LENGTH(strings_fpu_flags); ++i)
  {
    flags[offset + i].name = strings_fpu_flags[i];
    flags[offset + i].action = GetAccessedFlagActionString(instruction->fpu_flags, (ZyanU8)i);
  }

  PrintSectionHeader("FLAGS");

  PrintValueLabel("ACTIONS");

  ZyanU8 c = 0;
  for (ZyanUSize i = 0; i < ZYAN_ARRAY_LENGTH(flags); ++i)
  {
    if (flags[i].action == ZYAN_NULL)
    {
      continue;
    }
    if (c && (c % 8 == 0))
    {
      ZYAN_PRINTF("\n             ");
    }
    ++c;
    ZYAN_PRINTF("%s[%s%-4s%s: %s%-3s%s]%s ",
                CVT100_OUT(COLOR_VALUE_LABEL), CVT100_OUT(COLOR_VALUE_B),
                flags[i].name,
                CVT100_OUT(COLOR_VALUE_LABEL), CVT100_OUT(COLOR_VALUE_B),
                flags[i].action,
                CVT100_OUT(COLOR_VALUE_LABEL), CVT100_OUT(SCOLOR_DEFAULT));
  }
  ZYAN_PUTS("");

  // FLAGS_TO_STR(instruction->cpu_flags->tested)

  auto flags_to_str = [](ZydisAccessedFlagsMask flags)
  {
    std::string str;
    for (int i = 0; i < 32; i++)
    {
      if (flags & (1 << i))
      {
        if (!str.empty())
        {
          str += ", ";
        }
        str += strings_cpu_flags[i];
      }
    }
    return str;
  };

  if (instruction->cpu_flags->tested)
  {
    PRINT_VALUE_G("TESTED", " %s", flags_to_str(instruction->cpu_flags->tested).c_str());
  }

  /*
  auto wr = instruction->cpu_flags->modified |
            instruction->cpu_flags->set_0 |
            instruction->cpu_flags->set_1 |
            instruction->cpu_flags->undefined;
  if (wr)
  {
    PRINT_VALUE_G("WRITTEN", " %s", flags_to_str(wr).c_str());
  }
  */

  if (instruction->cpu_flags->modified)
  {
    PRINT_VALUE_G("MODIFIED", " %s", flags_to_str(instruction->cpu_flags->modified).c_str());
  }

  if (instruction->cpu_flags->set_0)
  {
    PRINT_VALUE_G("SET 0", " %s", flags_to_str(instruction->cpu_flags->set_0).c_str());
  }

  if (instruction->cpu_flags->set_1)
  {
    PRINT_VALUE_G("SET 1", " %s", flags_to_str(instruction->cpu_flags->set_1).c_str());
  }

  if (instruction->cpu_flags->undefined)
  {
    PRINT_VALUE_G("UNDEFINED", " %s", flags_to_str(instruction->cpu_flags->undefined).c_str());
  }
}

/**
 * Prints instruction AVX info.
 *
 * @param   instruction A pointer to the `ZydisDecodedInstruction` struct.
 */
static void PrintAVXInfo(const ZydisDecodedInstruction *instruction)
{
  static const char *strings_broadcast_mode[] =
      {
          "NONE",
          "1_TO_2",
          "1_TO_4",
          "1_TO_8",
          "1_TO_16",
          "1_TO_32",
          "1_TO_64",
          "2_TO_4",
          "2_TO_8",
          "2_TO_16",
          "4_TO_8",
          "4_TO_16",
          "8_TO_16"};
  ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(strings_broadcast_mode) == ZYDIS_BROADCAST_MODE_MAX_VALUE + 1);

  static const char *strings_mask_mode[] =
      {
          "INVALID",
          "DISABLED",
          "MERGING",
          "ZEROING",
          "CONTROL",
          "CONTROL_ZEROING"};
  ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(strings_mask_mode) == ZYDIS_MASK_MODE_MAX_VALUE + 1);

  static const char *strings_rounding_mode[] =
      {
          "DEFAULT",
          "RN",
          "RD",
          "RU",
          "RZ"};
  ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(strings_rounding_mode) == ZYDIS_ROUNDING_MODE_MAX_VALUE + 1);

  static const char *strings_swizzle_mode[] =
      {
          "NONE",
          "DCBA",
          "CDAB",
          "BADC",
          "DACB",
          "AAAA",
          "BBBB",
          "CCCC",
          "DDDD"};
  ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(strings_swizzle_mode) == ZYDIS_SWIZZLE_MODE_MAX_VALUE + 1);

  static const char *strings_conversion_mode[] =
      {
          "NONE",
          "FLOAT16",
          "SINT8",
          "UINT8",
          "SINT16",
          "UINT16"};
  ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(strings_conversion_mode) == ZYDIS_CONVERSION_MODE_MAX_VALUE + 1);

  PrintSectionHeader("AVX");

  PRINT_VALUE_B("VECTORLEN", "%03d", instruction->avx.vector_length);
  PRINT_VALUE_B("BROADCAST", "%s%s%s", strings_broadcast_mode[instruction->avx.broadcast.mode],
                CVT100_OUT(COLOR_VALUE_LABEL), instruction->avx.broadcast.is_static ? " (static)" : "");

  switch (instruction->encoding)
  {
  case ZYDIS_INSTRUCTION_ENCODING_EVEX:
    PRINT_VALUE_B("ROUNDING", "%s", strings_rounding_mode[instruction->avx.rounding.mode]);
    PRINT_VALUE_B("SAE", "%s", instruction->avx.has_sae ? "Y" : "N");
    PRINT_VALUE_R("MASK", "%s %s[%s%s%s]",
                  ZydisRegisterGetString(instruction->avx.mask.reg),
                  CVT100_OUT(COLOR_VALUE_LABEL), CVT100_OUT(COLOR_VALUE_B),
                  strings_mask_mode[instruction->avx.mask.mode], CVT100_OUT(COLOR_VALUE_LABEL));
    break;
  case ZYDIS_INSTRUCTION_ENCODING_MVEX:
    PRINT_VALUE_B("ROUNDING", "%s", strings_rounding_mode[instruction->avx.rounding.mode]);
    PRINT_VALUE_B("SAE", "%s", instruction->avx.has_sae ? "Y" : "N");
    PRINT_VALUE_R("MASK", "%s %s[%sMERGING%s]",
                  ZydisRegisterGetString(instruction->avx.mask.reg),
                  CVT100_OUT(COLOR_VALUE_LABEL), CVT100_OUT(COLOR_VALUE_B),
                  CVT100_OUT(COLOR_VALUE_LABEL));
    PRINT_VALUE_B("EH", "%s", instruction->avx.has_eviction_hint ? "Y" : "N");
    PRINT_VALUE_B("SWIZZLE", "%s", strings_swizzle_mode[instruction->avx.swizzle.mode]);
    PRINT_VALUE_B("CONVERT", "%s", strings_conversion_mode[instruction->avx.conversion.mode]);
    break;
  default:
    break;
  }
}

/**
 * Prints a tokenized instruction.
 *
 * @param   token   A pointer to the first token.
 */
void PrintTokenizedInstruction(const ZydisFormatterToken *token)
{
  ZyanStatus status = ZYAN_STATUS_SUCCESS;
  while (ZYAN_SUCCESS(status))
  {
    ZydisTokenType type;
    ZyanConstCharPointer value;
    if (!ZYAN_SUCCESS(status = ZydisFormatterTokenGetValue(token, &type, &value)))
    {
      PrintStatusError(status, "Failed to get token value");
      return;
    }

    const char *color;
    switch (token->type)
    {
    case ZYDIS_TOKEN_DELIMITER:
      ZYAN_FALLTHROUGH;
    case ZYDIS_TOKEN_PARENTHESIS_OPEN:
      ZYAN_FALLTHROUGH;
    case ZYDIS_TOKEN_PARENTHESIS_CLOSE:
      color = CVT100_OUT(COLOR_TOKEN_DEFAULT);
      break;
    case ZYDIS_TOKEN_PREFIX:
      color = CVT100_OUT(COLOR_TOKEN_PREFIX);
      break;
    case ZYDIS_TOKEN_MNEMONIC:
      color = CVT100_OUT(COLOR_TOKEN_MNEMONIC);
      break;
    case ZYDIS_TOKEN_REGISTER:
      color = CVT100_OUT(COLOR_TOKEN_REG);
      break;
    case ZYDIS_TOKEN_ADDRESS_ABS:
    case ZYDIS_TOKEN_ADDRESS_REL:
      color = CVT100_OUT(COLOR_TOKEN_ADDR);
      break;
    case ZYDIS_TOKEN_DISPLACEMENT:
      color = CVT100_OUT(COLOR_TOKEN_DISP);
      break;
    case ZYDIS_TOKEN_IMMEDIATE:
      color = CVT100_OUT(COLOR_TOKEN_IMM);
      break;
    case ZYDIS_TOKEN_TYPECAST:
      color = CVT100_OUT(ZYAN_VT100SGR_FG_WHITE);
      break;
    case ZYDIS_TOKEN_DECORATOR:
      color = CVT100_OUT(ZYAN_VT100SGR_FG_WHITE);
      break;
    default:
      color = CVT100_OUT(SCOLOR_DEFAULT);
      break;
    }
    ZYAN_PRINTF("%s%s", color, value);

    status = ZydisFormatterTokenNext(&token);
  }
  ZYAN_ASSERT(status == ZYAN_STATUS_OUT_OF_RANGE);

  ZYAN_PRINTF("%s\n", CVT100_OUT(SCOLOR_DEFAULT));
}

/**
 * Prints the formatted instruction disassembly.
 *
 * @param   instruction A pointer to the `ZydisDecodedInstruction` struct.
 * @param   operands    A pointer to the first `ZydisDecodedOperand` struct of the instruction.
 * @param   style       The formatter style.
 */
static void PrintDisassembly(const ZydisDecodedInstruction *instruction,
                             const ZydisDecodedOperand *operands, ZydisFormatterStyle style, ea_t ea)
{
  ZyanStatus status;
  ZydisFormatter formatter;

  switch (style)
  {
  case ZYDIS_FORMATTER_STYLE_ATT:
    if (!ZYAN_SUCCESS(status = ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_ATT)))
    {
      PrintStatusError(status, "Failed to initialize instruction-formatter");
      return;
    }
    PrintSectionHeader("AT&T");
    break;
  case ZYDIS_FORMATTER_STYLE_INTEL:
    if (!ZYAN_SUCCESS(status = ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL)) ||
        !ZYAN_SUCCESS(status = ZydisFormatterSetProperty(&formatter,
                                                         ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE)) ||
        !ZYAN_SUCCESS(status = ZydisFormatterSetProperty(&formatter,
                                                         ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE)))
    {
      PrintStatusError(status, "Failed to initialize instruction-formatter");
      return;
    }
    PrintSectionHeader("INTEL");
    break;
  default:
    ZYAN_UNREACHABLE;
  }

  ZyanU8 buffer[256];
  const ZydisFormatterToken *token;

  PrintValueLabel("ABSOLUTE");
  if (!ZYAN_SUCCESS(status = ZydisFormatterTokenizeInstruction(&formatter, instruction, operands,
                                                               instruction->operand_count_visible, buffer, sizeof(buffer), ea, &token, ZYAN_NULL)))
  {
    PrintStatusError(status, "Failed to tokenize instruction");
    return;
  }
  PrintTokenizedInstruction(token);
  PrintValueLabel("RELATIVE");
  if (!ZYAN_SUCCESS(status = ZydisFormatterTokenizeInstruction(&formatter, instruction, operands,
                                                               instruction->operand_count_visible, buffer, sizeof(buffer), ZYDIS_RUNTIME_ADDRESS_NONE,
                                                               &token, ZYAN_NULL)))
  {
    PrintStatusError(status, "Failed to tokenize instruction");
    return;
  }
  PrintTokenizedInstruction(token);
}

/**
 * Dumps basic instruction info.
 *
 * @param   decoder     A pointer to the `ZydisDecoder` instance.
 * @param   instruction A pointer to the `ZydisDecodedInstruction` struct.
 * @param   operands    A pointer to the first `ZydisDecodedOperand` struct of the instruction.
 */
static void PrintInstruction(const ZydisDecoder *decoder,
                             const ZydisDecodedInstruction *instruction, const ZydisDecodedOperand *operands, ea_t ea)
{
  static const char *opcode_maps[] =
      {
          "DEFAULT",
          "0F",
          "0F38",
          "0F3A",
          "MAP4",
          "MAP5",
          "MAP6",
          "MAP7",
          "0F0F",
          "XOP8",
          "XOP9",
          "XOPA"};
  ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(opcode_maps) == ZYDIS_OPCODE_MAP_MAX_VALUE + 1);

  static const char *instr_encodings[] =
      {
          "DEFAULT",
          "3DNOW",
          "XOP",
          "VEX",
          "EVEX",
          "MVEX"};
  ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(instr_encodings) == ZYDIS_INSTRUCTION_ENCODING_MAX_VALUE + 1);

  static const char *exception_classes[] =
      {
          "NONE",
          "SSE1",
          "SSE2",
          "SSE3",
          "SSE4",
          "SSE5",
          "SSE7",
          "AVX1",
          "AVX2",
          "AVX3",
          "AVX4",
          "AVX5",
          "AVX6",
          "AVX7",
          "AVX8",
          "AVX11",
          "AVX12",
          "E1",
          "E1NF",
          "E2",
          "E2NF",
          "E3",
          "E3NF",
          "E4",
          "E4NF",
          "E5",
          "E5NF",
          "E6",
          "E6NF",
          "E7NM",
          "E7NM128",
          "E9NF",
          "E10",
          "E10NF",
          "E11",
          "E11NF",
          "E12",
          "E12NP",
          "K20",
          "K21",
          "AMXE1",
          "AMXE2",
          "AMXE3",
          "AMXE4",
          "AMXE5",
          "AMXE6"};
  ZYAN_ASSERT(ZYAN_ARRAY_LENGTH(exception_classes) == ZYDIS_EXCEPTION_CLASS_MAX_VALUE + 1);

  static const struct
  {
    ZydisInstructionAttributes attribute_mask;
    const char *str;
  } attribute_map[] =
      {
          {ZYDIS_ATTRIB_HAS_MODRM, "HAS_MODRM"},
          {ZYDIS_ATTRIB_HAS_SIB, "HAS_SIB"},
          {ZYDIS_ATTRIB_HAS_REX, "HAS_REX"},
          {ZYDIS_ATTRIB_HAS_XOP, "HAS_XOP"},
          {ZYDIS_ATTRIB_HAS_VEX, "HAS_VEX"},
          {ZYDIS_ATTRIB_HAS_EVEX, "HAS_EVEX"},
          {ZYDIS_ATTRIB_HAS_MVEX, "HAS_MVEX"},
          {ZYDIS_ATTRIB_IS_RELATIVE, "IS_RELATIVE"},
          {ZYDIS_ATTRIB_IS_PRIVILEGED, "IS_PRIVILEGED"},
          {ZYDIS_ATTRIB_CPUFLAG_ACCESS, "CPUFLAG_ACCESS"},
          {ZYDIS_ATTRIB_CPU_STATE_CR, "CPU_STATE_CR"},
          {ZYDIS_ATTRIB_CPU_STATE_CW, "CPU_STATE_CW"},
          {ZYDIS_ATTRIB_FPU_STATE_CR, "FPU_STATE_CR"},
          {ZYDIS_ATTRIB_FPU_STATE_CW, "FPU_STATE_CW"},
          {ZYDIS_ATTRIB_XMM_STATE_CR, "XMM_STATE_CR"},
          {ZYDIS_ATTRIB_XMM_STATE_CW, "XMM_STATE_CW"},
          {ZYDIS_ATTRIB_ACCEPTS_LOCK, "ACCEPTS_LOCK"},
          {ZYDIS_ATTRIB_ACCEPTS_REP, "ACCEPTS_REP"},
          {ZYDIS_ATTRIB_ACCEPTS_REPE, "ACCEPTS_REPE"},
          {ZYDIS_ATTRIB_ACCEPTS_REPZ, "ACCEPTS_REPZ"},
          {ZYDIS_ATTRIB_ACCEPTS_REPNE, "ACCEPTS_REPNE"},
          {ZYDIS_ATTRIB_ACCEPTS_REPNZ, "ACCEPTS_REPNZ"},
          {ZYDIS_ATTRIB_ACCEPTS_BND, "ACCEPTS_BND"},
          {ZYDIS_ATTRIB_ACCEPTS_XACQUIRE, "ACCEPTS_XACQUIRE"},
          {ZYDIS_ATTRIB_ACCEPTS_XRELEASE, "ACCEPTS_XRELEASE"},
          {ZYDIS_ATTRIB_ACCEPTS_HLE_WITHOUT_LOCK, "ACCEPTS_HLE_WITHOUT_LOCK"},
          {ZYDIS_ATTRIB_ACCEPTS_BRANCH_HINTS, "ACCEPTS_BRANCH_HINTS"},
          {ZYDIS_ATTRIB_ACCEPTS_SEGMENT, "ACCEPTS_SEGMENT"},
          {ZYDIS_ATTRIB_HAS_LOCK, "HAS_LOCK"},
          {ZYDIS_ATTRIB_HAS_REP, "HAS_REP"},
          {ZYDIS_ATTRIB_HAS_REPE, "HAS_REPE"},
          {ZYDIS_ATTRIB_HAS_REPZ, "HAS_REPZ"},
          {ZYDIS_ATTRIB_HAS_REPNE, "HAS_REPNE"},
          {ZYDIS_ATTRIB_HAS_REPNZ, "HAS_REPNZ"},
          {ZYDIS_ATTRIB_HAS_BND, "HAS_BND"},
          {ZYDIS_ATTRIB_HAS_XACQUIRE, "HAS_XACQUIRE"},
          {ZYDIS_ATTRIB_HAS_XRELEASE, "HAS_XRELEASE"},
          {ZYDIS_ATTRIB_HAS_BRANCH_NOT_TAKEN, "HAS_BRANCH_NOT_TAKEN"},
          {ZYDIS_ATTRIB_HAS_BRANCH_TAKEN, "HAS_BRANCH_TAKEN"},
          {ZYDIS_ATTRIB_HAS_SEGMENT, "HAS_SEGMENT"},
          {ZYDIS_ATTRIB_HAS_SEGMENT_CS, "HAS_SEGMENT_CS"},
          {ZYDIS_ATTRIB_HAS_SEGMENT_SS, "HAS_SEGMENT_SS"},
          {ZYDIS_ATTRIB_HAS_SEGMENT_DS, "HAS_SEGMENT_DS"},
          {ZYDIS_ATTRIB_HAS_SEGMENT_ES, "HAS_SEGMENT_ES"},
          {ZYDIS_ATTRIB_HAS_SEGMENT_FS, "HAS_SEGMENT_FS"},
          {ZYDIS_ATTRIB_HAS_SEGMENT_GS, "HAS_SEGMENT_GS"},
          {ZYDIS_ATTRIB_HAS_OPERANDSIZE, "HAS_OPERANDSIZE"},
          {ZYDIS_ATTRIB_HAS_ADDRESSSIZE, "HAS_ADDRESSSIZE"},
          {ZYDIS_ATTRIB_ACCEPTS_NOTRACK, "ACCEPTS_NOTRACK"},
          {ZYDIS_ATTRIB_HAS_NOTRACK, "HAS_NOTRACK"}};

  PrintSectionHeader("BASIC");
  PrintValueLabel("MNEMONIC");
  ZYAN_PRINTF("%s%s%s [ENC: %s%s%s, MAP: %s%s%s, OPC: %s0x%02X%s]%s\n",
              CVT100_OUT(COLOR_VALUE_R), ZydisMnemonicGetString(instruction->mnemonic),
              CVT100_OUT(COLOR_VALUE_LABEL),
              CVT100_OUT(COLOR_VALUE_B), instr_encodings[instruction->encoding],
              CVT100_OUT(COLOR_VALUE_LABEL),
              CVT100_OUT(COLOR_VALUE_B), opcode_maps[instruction->opcode_map],
              CVT100_OUT(COLOR_VALUE_LABEL),
              CVT100_OUT(COLOR_VALUE_G), instruction->opcode,
              CVT100_OUT(COLOR_VALUE_LABEL), CVT100_OUT(SCOLOR_DEFAULT));
  qstring cmt;
  get_auto_comment(&cmt, ea);
  PRINT_VALUE_B("DESC", "%s", cmt.c_str());
  PRINT_VALUE_G("LENGTH", "%2d", instruction->length);
  PRINT_VALUE_G("SSZ", "%2d", instruction->stack_width);
  PRINT_VALUE_G("EOSZ", "%2d", instruction->operand_width);
  PRINT_VALUE_G("EASZ", "%2d", instruction->address_width);
  PRINT_VALUE_B("CATEGORY", "%s", ZydisCategoryGetString(instruction->meta.category));
  PRINT_VALUE_B("ISA-SET", "%s", ZydisISASetGetString(instruction->meta.isa_set));
  PRINT_VALUE_B("ISA-EXT", "%s", ZydisISAExtGetString(instruction->meta.isa_ext));
  PRINT_VALUE_B("EXCEPTIONS", "%s", exception_classes[instruction->meta.exception_class]);

  if (instruction->attributes)
  {
    PrintValueLabel("ATTRIBUTES");

    ZYAN_PRINTF(CVT100_OUT(COLOR_VALUE_B));
    ZyanUSize len_total = 13;
    for (ZyanUSize i = 0; i < ZYAN_ARRAY_LENGTH(attribute_map); ++i)
    {
      if (instruction->attributes & attribute_map[i].attribute_mask)
      {
        const ZyanUSize len = ZYAN_STRLEN(attribute_map[i].str);
        if (len_total + len > 109)
        {
          len_total = 13;
          ZYAN_PRINTF("\n             ");
        }
        len_total += ZYAN_PRINTF("%s ", attribute_map[i].str);
      }
    }
    ZYAN_PUTS(CVT100_OUT(SCOLOR_DEFAULT));
  }

#if !defined(ZYDIS_DISABLE_ENCODER)

  PrintValueLabel("OPTIMIZED");
  PrintSizeOptimizedForm(decoder, instruction, operands, instruction->operand_count_visible);

#else
  ZYAN_UNUSED(decoder);
#endif

  if (instruction->operand_count > 0)
  {
    ZYAN_PUTS("");
    PrintOperands(instruction, operands);
  }

  if (instruction->attributes & ZYDIS_ATTRIB_CPUFLAG_ACCESS)
  {
    ZYAN_PUTS("");
    PrintFlags(instruction);
  }

  if ((instruction->encoding == ZYDIS_INSTRUCTION_ENCODING_XOP) ||
      (instruction->encoding == ZYDIS_INSTRUCTION_ENCODING_VEX) ||
      (instruction->encoding == ZYDIS_INSTRUCTION_ENCODING_EVEX) ||
      (instruction->encoding == ZYDIS_INSTRUCTION_ENCODING_MVEX))
  {
    ZYAN_PUTS("");
    PrintAVXInfo(instruction);
  }

  ZYAN_PUTS("");
  PrintDisassembly(instruction, operands, ZYDIS_FORMATTER_STYLE_ATT, ea);
  ZYAN_PUTS("");
  PrintDisassembly(instruction, operands, ZYDIS_FORMATTER_STYLE_INTEL, ea);
}

void decode(ea_t ea)
{
  ZydisDecoder decoder;
  ZydisMachineMode machine_mode;
  ZydisStackWidth stack_width;
  ZyanU8 hexbytes_index = 2;

  auto seg = getseg(ea);
  if (seg == nullptr)
  {
    ZYAN_PRINTF("Failed to get segment for ea %a\n", ea);
    return;
  }

  auto bitness = seg->bitness;
  switch (bitness)
  {
  case 0:
    stack_width = ZYDIS_STACK_WIDTH_16;
    machine_mode = ZYDIS_MACHINE_MODE_REAL_16;
    break;
  case 1:
    stack_width = ZYDIS_STACK_WIDTH_32;
    machine_mode = ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
    break;
  case 2:
    stack_width = ZYDIS_STACK_WIDTH_64;
    machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
    break;
  default:
    return;
  }

  ZyanStatus status = ZydisDecoderInit(&decoder, machine_mode, stack_width);
  if (!ZYAN_SUCCESS(status))
  {
    ZYAN_PRINTF("Failed to initialize decoder\n");
    return;
  }

  ZyanU8 data[ZYDIS_MAX_INSTRUCTION_LENGTH];
  ZyanU8 byte_length = ZYDIS_MAX_INSTRUCTION_LENGTH;

  if (get_bytes(data, ZYDIS_MAX_INSTRUCTION_LENGTH, ea) <= 0)
  {
    ZYAN_PRINTF("Failed to read %d bytes at %a\n", ZYDIS_MAX_INSTRUCTION_LENGTH, ea);
    return;
  }

  ZydisDecodedInstruction instruction;
  ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

  status = ZydisDecoderDecodeFull(&decoder, &data, byte_length, &instruction, operands);
  if (!ZYAN_SUCCESS(status))
  {
    PrintStatusError(status, "Failed to decode instruction");
    return;
  }

  PrintInstruction(&decoder, &instruction, operands, ea);
  ZYAN_PUTS("");
  PrintSectionHeader("SEGMENTS");
  PrintSegments(&instruction, &data[0], ZYAN_TRUE);
}

void decode_segments(ea_t ea, ZyanBool print_hints)
{
  ZydisDecoder decoder;
  ZydisMachineMode machine_mode;
  ZydisStackWidth stack_width;
  ZyanU8 hexbytes_index = 2;

  auto seg = getseg(ea);
  if (seg == nullptr)
  {
    ZYAN_PRINTF("Failed to get segment for ea %a\n", ea);
    return;
  }

  auto bitness = seg->bitness;
  switch (bitness)
  {
  case 0:
    stack_width = ZYDIS_STACK_WIDTH_16;
    machine_mode = ZYDIS_MACHINE_MODE_REAL_16;
    break;
  case 1:
    stack_width = ZYDIS_STACK_WIDTH_32;
    machine_mode = ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
    break;
  case 2:
    stack_width = ZYDIS_STACK_WIDTH_64;
    machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
    break;
  default:
    return;
  }

  ZyanStatus status = ZydisDecoderInit(&decoder, machine_mode, stack_width);
  if (!ZYAN_SUCCESS(status))
  {
    ZYAN_PRINTF("Failed to initialize decoder\n");
    return;
  }

  ZyanU8 data[ZYDIS_MAX_INSTRUCTION_LENGTH];
  ZyanU8 byte_length = ZYDIS_MAX_INSTRUCTION_LENGTH;

  if (get_bytes(data, ZYDIS_MAX_INSTRUCTION_LENGTH, ea) <= 0)
  {
    // ZYAN_PRINTF("Failed to read %d bytes at %a\n", ZYDIS_MAX_INSTRUCTION_LENGTH, ea);
    return;
  }

  ZydisDecodedInstruction instruction;
  ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
  // msg("Decoding %d bytes at %llx\n", byte_length, ea);

  status = ZydisDecoderDecodeFull(&decoder, &data, byte_length, &instruction, operands);
  if (!ZYAN_SUCCESS(status))
  {
    msg("Failed to decode instruction\n");
    // PrintStatusError(status, "Failed to decode instruction");
    return;
  }
  // msg("Decoded %d bytes at %llx\n", byte_length, ea);

  // PrintInstruction(&decoder, &instruction, operands, ea);
  // ZYAN_PUTS("");
  // PrintSectionHeader("SEGMENTS");
  PrintSegments(&instruction, &data[0], print_hints);
}

//--------------------------------------------------------------------------
ssize_t idaapi plugin_ctx_t::on_event(ssize_t code, va_list va)
{
  switch (code)
  {
  case ui_get_custom_viewer_hint:
  {
    ///< cb: ui wants to display a hint for a viewer (idaview or custom).
    ///< Every subscriber is supposed to append the hint lines
    ///< to HINT and increment IMPORTANT_LINES accordingly.
    ///< Completely overwriting the existing lines in HINT
    ///< is possible but not recommended.
    ///< If the REG_HINTS_MARKER sequence is found in the
    ///< returned hints string, it will be replaced with the
    ///< contents of the "regular" hints.
    ///< If the SRCDBG_HINTS_MARKER sequence is found in the
    ///< returned hints string, it will be replaced with the
    ///< contents of the source-level debugger-generated hints.
    ///< The following keywords might appear at the beginning of the
    ///< returned hints:
    ///< HIGHLIGHT text\n
    ///<   where text will be highlighted
    ///< CAPTION caption\n
    ///<   caption for the hint widget
    ///< \param[out] hint             (::qstring *) the output string,
    ///<                              on input contains hints from the previous subscribes
    ///< \param viewer                (TWidget*) viewer
    ///< \param place                 (::place_t *) current position in the viewer
    ///< \param[out] important_lines  (int *) number of important lines,
    ///<                                     should be incremented,
    ///<                                     if zero, the result is ignored
    ///< \retval 0 continue collecting hints with other subscribers
    ///< \retval 1 stop collecting hints
    qstring &hint = *va_arg(va, qstring *);
    TWidget *viewer = va_arg(va, TWidget *);
    place_t *place = va_arg(va, place_t *);
    int *important_lines = va_arg(va, int *);
    if (widget == nullptr)
      return 0;
    if (place == nullptr)
      return 0;
    if (widget != viewer) // our viewer
      return 0;

    if (place == nullptr)
      return 0;
    simpleline_place_t *spl = (simpleline_place_t *)place;
    hint.cat_sprnt("Hint for line %u\n", spl->n);
    *important_lines += 1;
    return 1; // we handled it
  }

  case ui_widget_invisible:
  {
    TWidget *w = va_arg(va, TWidget *);
    if (w == widget)
    {
      widget = nullptr;
      lines.qclear();
      unhook_event_listener(HT_UI, this);
    }
  }
  break;
  case ui_updating_actions:
  {
    /*
    ui_updating_actions,  ///< cb: IDA is about to update all actions. If your plugin
                            ///< needs to perform expensive operations more than once
                            ///< (e.g., once per action it registers), you should do them
                            ///< only once, right away.
                            ///< \param ctx  (::action_update_ctx_t *)
                            ///< \return void
     */
    action_update_ctx_t *ctx = va_arg(va, action_update_ctx_t *);
    if (ctx->cur_ea == BADADDR)
      return 0;

    if (!is_mapped(ctx->cur_ea))
      return 0;

    if (ctx->cur_ea == current_ea)
      return 0;

    current_ea = ctx->cur_ea;

    // qstring disasm;
    // generate_disasm_line(&disasm, current_ea, GENDSM_FORCE_CODE);
    decode_at_current_ea();
  }
  break;
  }
  return 0;
}

void plugin_ctx_t::decode_at_current_ea()
{
  logger.clear();
  decode(current_ea);
  lines.clear();
  lines.swap(logger.get_lines());

  refresh_custom_viewer(widget);
}

//-------------------------------------------------------------------------
static const custom_viewer_handlers_t handlers(
    ct_keyboard,
    nullptr, // popup
    nullptr, // mouse_moved
    nullptr, // click
    nullptr, // dblclick
    ct_curpos,
    nullptr,  // close
    nullptr,  // help
    nullptr); // adjust_place

//---------------------------------------------------------------------------
// Create a custom view window
bool idaapi plugin_ctx_t::run(size_t)
{
  TWidget *w = find_widget(WINDOW_NAME);
  if (w != nullptr)
  {
    activate_widget(w, true);
    return true;
  }

  current_ea = get_screen_ea();
  decode_at_current_ea();

  // create two place_t objects: for the minimal and maximal locations
  simpleline_place_t s1;
  simpleline_place_t s2(lines.size() - 1);

  // create a custom viewer
  widget = create_custom_viewer(WINDOW_NAME, &s1, &s2, &s1, nullptr, &lines, &handlers, this);
  // also set the ui event callback
  hook_event_listener(HT_UI, this);
  // finally display the form on the screen
  display_widget(widget, WOPN_DP_RIGHT | WOPN_RESTORE);

  // We will always want those actions to be present in the context menu,
  // so instead of relying on `ui_populating_widget_popup` we can attach
  // them once and for all here

  return true;
}

void plugin_ctx_t::show_demo()
{
  lines.clear();
  for (auto &&line : sample_text)
  {
    lines.push_back(simpleline_t(line.text));
    lines.back().bgcolor = line.color;
  }
  refresh_custom_viewer(widget);
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  if constexpr (ONLY_X86)
  {
    if (PH.id != PLFM_386)
    {
      msg("[zydis] Unsupported processor type\n");
      return nullptr;
    }
  }

  addon_info_t addon_info;
  addon_info.id = "milankovo.zydis";
  addon_info.name = "Zydis info";
  addon_info.producer = "Milanek";
  addon_info.url = "https://github.com/milankovo/zydisinfo";
  addon_info.version = "1.1.1";
  register_addon(&addon_info);

  auto ctx = new plugin_ctx_t;

  return ctx;
}

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
    {
        IDP_INTERFACE_VERSION,
        PLUGIN_MULTI, // plugin flags
        init,         // initialize

        nullptr,
        nullptr,

        "View with instruction metadata as reported by the Zydis library", // long comment about the plugin
        "",                                                                // multiline help about the plugin
        "Zydis info",                                                      // the preferred short name of the plugin
        ""                                                                 // the preferred hotkey to run the plugin
};
