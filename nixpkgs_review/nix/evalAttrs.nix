{ attr-json }:

with builtins;
let
  pkgs = import <nixpkgs> {
    config = import (getEnv "NIXPKGS_CONFIG") // {
      allowBroken = false;
    };
  };

  inherit (pkgs) lib;

  attrs = fromJSON (readFile attr-json);
  getProperties = name:
    let
      attrPath = lib.splitString "." name;
      pkg = lib.attrByPath attrPath null pkgs;
      exists = lib.hasAttrByPath attrPath pkgs;
    in
    if pkg == null then
      [
        (lib.nameValuePair name {
          inherit exists;
          broken = true;
          path = null;
          drvPath = null;
        })
      ]
    else
      lib.flip map pkg.outputs or [ "out" ] (output:
        let
          # some packages are set to null if they aren't compatible with a platform or package set
          maybePath = tryEval "${lib.getOutput output pkg}";
          maybePosition = builtins.tryEval pkg.meta.position or null;
          broken = !exists || !maybePath.success;
        in
        lib.nameValuePair
          (if output == "out" then name else "${name}.${output}")
          {
            inherit exists broken;
            path = if !broken then maybePath.value else null;
            drvPath = if !broken then pkg.drvPath else null;
            position = if maybePosition.success then maybePosition.value else null;
          }
      );
in

listToAttrs (concatMap getProperties attrs)
