import AppKit
for size in [120, 180] {
    let image = NSImage(size: NSSize(width: size, height: size))
    image.lockFocus()
    NSColor(calibratedRed: 0.09, green: 0.35, blue: 0.62, alpha: 1).setFill()
    NSBezierPath(rect: NSRect(x: 0, y: 0, width: size, height: size)).fill()
    let text = "清" as NSString
    let attributes: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: CGFloat(size) * 0.59, weight: .medium), .foregroundColor: NSColor.white]
    let measured = text.size(withAttributes: attributes)
    text.draw(at: NSPoint(x: (CGFloat(size) - measured.width) / 2, y: (CGFloat(size) - measured.height) / 2), withAttributes: attributes)
    image.unlockFocus()
    let bitmap = NSBitmapImageRep(data: image.tiffRepresentation!)!
    try bitmap.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: CommandLine.arguments[1] + "/AppIcon60x60@\(size / 60)x.png"))
}
