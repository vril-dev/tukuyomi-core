-- The Japanese sources put each sentence on its own line. A line break inside a paragraph is a space in HTML, and
-- Japanese text has no spaces, so a line break next to a Japanese character (or a full-width mark) is dropped.
local function wide(s, at_end)
  if not s then
    return false
  end
  local pattern = at_end and "[\227-\233\239][\128-\191][\128-\191]$" or "^[\227-\233\239][\128-\191][\128-\191]"
  return s:match(pattern) ~= nil
end

function Inlines(inlines)
  for i = #inlines, 1, -1 do
    if inlines[i].t == "SoftBreak" then
      local before, after = inlines[i - 1], inlines[i + 1]
      if (before and before.t == "Str" and wide(before.text, true))
          or (after and after.t == "Str" and wide(after.text, false)) then
        inlines:remove(i)
      end
    end
  end
  return inlines
end
