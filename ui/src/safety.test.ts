import {
  copyBoundedText,
  csvCell,
  downloadText,
  redactError,
  safeFilename,
  safeInternalUrl
} from "./safety";

describe("central browser safety controls", () => {
  it("allows only same-origin navigation", () => {
    expect(safeInternalUrl("/audit?limit=10")).toBe("/audit?limit=10");
    expect(safeInternalUrl("https://evil.invalid/steal")).toBeNull();
    expect(safeInternalUrl("javascript:alert(1)")).toBeNull();
    expect(safeInternalUrl("http://[invalid")).toBeNull();
  });

  it("neutralizes CSV formulas and unsafe filenames", () => {
    expect(csvCell('=HYPERLINK("https://evil.invalid")')).toBe(
      '"\'=HYPERLINK(""https://evil.invalid"")"'
    );
    expect(safeFilename("../../secret?.csv")).toBe("..-..-secret-.csv");
    expect(safeFilename("***")).toBe("---");
  });

  it("does not expose unknown error details", () => {
    expect(redactError(new Error("secret tenant payload"))).not.toContain("secret");
    expect(redactError("raw failure")).toContain("failed safely");
  });

  it("bounds downloads and clipboard writes", async () => {
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, "click")
      .mockImplementation(() => {
        return undefined;
      });
    const create = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:test");
    const revoke = vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => undefined);
    downloadText("report.json", "application/json", "{}");
    expect(click).toHaveBeenCalledOnce();
    expect(create).toHaveBeenCalledOnce();
    expect(revoke).toHaveBeenCalledWith("blob:test");
    expect(() => downloadText("bad.html", "text/html", "<b>bad</b>")).toThrow();

    const writeText = vi.fn<(_: string) => Promise<void>>().mockResolvedValue();
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText }
    });
    await copyBoundedText("bounded");
    expect(writeText).toHaveBeenCalledWith("bounded");
    await expect(copyBoundedText("x".repeat(4097))).rejects.toThrow();
  });
});
