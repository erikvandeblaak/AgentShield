import { describe, expect, it } from "vitest";
import { parsePackages, stripVersion, supplyKind } from "./packages";
import { extractSecretRefs } from "./secrets";

describe("parsePackages", () => {
  it("parses installs and ignores flags, versions and paths", () => {
    expect(parsePackages("npm install --save-dev lodash@4.17.21 @types/node ./local")).toEqual([
      { manager: "npm", name: "lodash", action: "install" },
      { manager: "npm", name: "@types/node", action: "install" },
    ]);
    expect(parsePackages("sudo pip3 install -r requirements.txt reqeusts==2.0")).toEqual([
      { manager: "pip", name: "reqeusts", action: "install" },
    ]);
    expect(parsePackages("python -m pip install --index-url http://x.invalid/simple flask")).toEqual([
      { manager: "pip", name: "flask", action: "install" },
    ]);
  });

  it("parses fetch-and-run launchers as execute", () => {
    expect(parsePackages("npx -y some-tool --flag arg")).toEqual([{ manager: "npx", name: "some-tool", action: "execute" }]);
    expect(parsePackages("cd app && pnpm dlx create-thing@latest my-app")).toEqual([
      { manager: "pnpm dlx", name: "create-thing", action: "execute" },
    ]);
  });

  it("returns nothing for unrelated commands", () => {
    expect(parsePackages("git status; ls -la | grep npm")).toEqual([]);
    expect(parsePackages("npm config set registry http://registry.example.invalid")).toEqual([]);
    expect(parsePackages("npm test")).toEqual([]);
  });

  it("strips version specifiers", () => {
    expect(stripVersion("@scope/pkg@1.2.3")).toBe("@scope/pkg");
    expect(stripVersion("requests[socks]>=2")).toBe("requests");
  });

  it("classifies finding ids", () => {
    expect(supplyKind("package.typosquat_suspect")).toBe("typosquat");
    expect(supplyKind("package.registry_override")).toBe("registry");
    expect(supplyKind("package.remote_execute")).toBe("remote");
    expect(supplyKind("package.install")).toBe("scripts");
    expect(supplyKind("something.else")).toBe("other");
  });
});

describe("extractSecretRefs", () => {
  it("extracts only [kind:fingerprint] placeholders and dedupes", () => {
    expect(extractSecretRefs("export K=[aws_secret:3fa9c1d2] x [aws_secret:3fa9c1d2] [redacted:dsn] [github_token:9BE2F0A1]")).toEqual([
      { kind: "aws_secret", fingerprint: "3fa9c1d2" },
      { kind: "github_token", fingerprint: "9be2f0a1" },
    ]);
  });
});
