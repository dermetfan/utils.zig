rec {
  # copied from nixpkgs
  isDerivation = value: value.type or null == "derivation";

  flattenDepth = depth: x:
    if builtins.isList x && (depth == null || depth >= 0)
    then
      builtins.concatMap
      (flattenDepth (
        if depth != null
        then depth - 1
        else null
      ))
      x
    else [x];

  flatten = flattenDepth null;

  collectAttrPaths = predicate: attrs: let
    internal = path: attrs: let
      inherit
        (
          builtins.partition
          (attrName: predicate attrs.${attrName})
          (builtins.attrNames attrs)
        )
        right
        wrong
        ;
    in
      map (attrName: path ++ [attrName]) right
      ++ (
        if attrs.recurseIntoAttrs or true
        then
          flattenDepth 1 (
            map
            (
              attrName:
                internal
                (path ++ [attrName])
                attrs.${attrName}
            )
            (
              builtins.filter
              (attrName: builtins.isAttrs attrs.${attrName})
              wrong
            )
          )
        else []
      );
  in
    internal [] attrs;

  # TODO properly copy `showAttrPath` from nixpkgs
  showAttrPath = builtins.concatStringsSep ".";

  # copied from nixpkgs and simplified
  attrByPath = path: attrs: let
    attr = builtins.head path;
  in
    if path == []
    then attrs
    else attrByPath (builtins.tail path) attrs.${attr};
}
