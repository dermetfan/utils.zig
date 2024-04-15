let
  recurse = found: doRecurse: value:
    if lib.isDerivation value
    then found ++ [value]
    else if builtins.isList value
    then lib.flattenDepth 1 (map (recurse found doRecurse) value)
    else if builtins.isAttrs value
    then let
      inherit (builtins.partition lib.isDerivation (builtins.attrValues value)) right wrong;
    in
      found
      ++ map (elem: elem) right
      ++ lib.flattenDepth 1 (map (
          elem:
            if builtins.isAttrs elem && elem.recurseForDerivations or value.recurseForDerivations or doRecurse
            then recurse [] true elem
            else []
        )
        wrong)
    else found;
in
  recurse [] false expression
