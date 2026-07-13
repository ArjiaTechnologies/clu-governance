#!/usr/bin/env swift
// Generates the README GIF from actual `agent-preflight` CLI JSON in a disposable workspace.
// Requires only the macOS SDK (AppKit + ImageIO) and Python 3.12; it is not runtime code.

import AppKit
import Foundation
import ImageIO
import UniformTypeIdentifiers

let width = 1440
let height = 810

func usage() -> Never {
fputs("usage: swift docs/assets/generate_policy_evidence_demo.swift --repo-root <path> [--output <gif>] [--frames-dir <directory>]\n", stderr)
    exit(64)
}

var arguments = Array(CommandLine.arguments.dropFirst())
var repositoryRoot: String?
var output = "docs/assets/clu-governance-policy-evidence-demo.gif"
var framesDirectory: String?
while !arguments.isEmpty {
    let argument = arguments.removeFirst()
    switch argument {
    case "--repo-root":
        guard !arguments.isEmpty else { usage() }
        repositoryRoot = arguments.removeFirst()
    case "--output":
        guard !arguments.isEmpty else { usage() }
        output = arguments.removeFirst()
    case "--frames-dir":
        guard !arguments.isEmpty else { usage() }
        framesDirectory = arguments.removeFirst()
    default:
        usage()
    }
}
guard let repositoryRoot else { usage() }

func realEvidence(repositoryRoot: String) throws -> (allow: [String: Any], deny: [String: Any]) {
    let script = """
import json, subprocess, sys, tempfile
from pathlib import Path
from clu_governance.source_mutation_policy_gate import demo_init

def invoke(envelope):
    result = subprocess.run(
        [sys.executable, "-B", "-m", "clu_governance.cli", "agent-preflight", "--json"],
        input=json.dumps(envelope, sort_keys=True), text=True, capture_output=True, check=False,
    )
    if result.stderr:
        raise SystemExit(result.stderr)
    payload = json.loads(result.stdout)
    return result.returncode, payload

with tempfile.TemporaryDirectory(prefix="clu-readme-demo-", dir=Path.cwd()) as directory:
    init = demo_init(Path(directory) / "workspace", reset=True)
    common = {
        "schema_name": "clu_governance_agent_preflight_input.v1",
        "schema_version": "1",
        "policy_path": init["policy_path"],
        "source_root": init["demo_repo"],
        "event_timestamp": "2026-07-13T00:00:00Z",
        "sequence_index": 1,
    }
    allow_code, allow = invoke({**common, "request_path": init["allowed_request_path"]})
    deny_code, deny = invoke({**common, "request_path": init["denied_request_path"], "sequence_index": 2})
    if allow_code != 0 or deny_code != 2:
        raise SystemExit("unexpected agent-preflight result")
    print(json.dumps({"allow": allow, "deny": deny}, sort_keys=True))
"""
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = ["python3.12", "-B", "-c", script]
    process.currentDirectoryURL = URL(fileURLWithPath: repositoryRoot)
    var environment = ProcessInfo.processInfo.environment
    environment["PYTHONPATH"] = URL(fileURLWithPath: repositoryRoot).appendingPathComponent("src").path
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    process.environment = environment
    let standardOutput = Pipe()
    let standardError = Pipe()
    process.standardOutput = standardOutput
    process.standardError = standardError
    try process.run()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else {
        let message = String(data: standardError.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "unknown Python failure"
        throw NSError(domain: "readme-demo", code: Int(process.terminationStatus), userInfo: [NSLocalizedDescriptionKey: message])
    }
    let data = standardOutput.fileHandleForReading.readDataToEndOfFile()
    let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
    guard let allow = object?["allow"] as? [String: Any], let deny = object?["deny"] as? [String: Any] else {
        throw NSError(domain: "readme-demo", code: 1, userInfo: [NSLocalizedDescriptionKey: "CLI JSON did not contain allow and deny evidence"])
    }
    return (allow, deny)
}

func color(_ hex: UInt32, _ alpha: CGFloat = 1) -> NSColor {
    NSColor(
        red: CGFloat((hex >> 16) & 0xFF) / 255,
        green: CGFloat((hex >> 8) & 0xFF) / 255,
        blue: CGFloat(hex & 0xFF) / 255,
        alpha: alpha
    )
}

func rounded(_ context: CGContext, x: CGFloat, y: CGFloat, width: CGFloat, height: CGFloat, radius: CGFloat, fill: NSColor, stroke: NSColor? = nil, lineWidth: CGFloat = 1) {
    let rect = CGRect(x: x, y: y, width: width, height: height)
    let path = CGPath(roundedRect: rect, cornerWidth: radius, cornerHeight: radius, transform: nil)
    context.addPath(path)
    context.setFillColor(fill.cgColor)
    context.fillPath()
    if let stroke {
        context.addPath(path)
        context.setStrokeColor(stroke.cgColor)
        context.setLineWidth(lineWidth)
        context.strokePath()
    }
}

func text(_ context: CGContext, _ value: String, x: CGFloat, y: CGFloat, size: CGFloat, weight: NSFont.Weight = .regular, color: NSColor, monospaced: Bool = false) {
    let font = monospaced ? NSFont.monospacedSystemFont(ofSize: size, weight: weight) : NSFont.systemFont(ofSize: size, weight: weight)
    let attributes: [NSAttributedString.Key: Any] = [.font: font, .foregroundColor: color]
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(cgContext: context, flipped: true)
    (value as NSString).draw(at: NSPoint(x: x, y: y), withAttributes: attributes)
    NSGraphicsContext.restoreGraphicsState()
}

func divider(_ context: CGContext, y: CGFloat) {
    context.setStrokeColor(color(0x263449).cgColor)
    context.setLineWidth(1)
    context.move(to: CGPoint(x: 112, y: y))
    context.addLine(to: CGPoint(x: 1328, y: y))
    context.strokePath()
}

func bool(_ evidence: [String: Any], _ key: String) -> String {
    (evidence[key] as? Bool) == true ? "true" : "false"
}

func verifiedValue(_ evidence: [String: Any], _ key: String) -> String {
    if let value = evidence[key] as? String, value.count > 18 {
        return "\(value.prefix(8))…\(value.suffix(8))"
    }
    if let value = evidence[key] as? String { return value }
    return bool(evidence, key)
}

enum Scene { case opening, allowCommand, allowEvidence, denyCommand, denyEvidence, boundary }

func render(scene: Scene, allow: [String: Any], deny: [String: Any]) -> CGImage {
    let context = CGContext(
        data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0,
        space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
    )!
    context.translateBy(x: 0, y: CGFloat(height))
    context.scaleBy(x: 1, y: -1)
    context.setFillColor(color(0x09111F).cgColor)
    context.fill(CGRect(x: 0, y: 0, width: width, height: height))
    rounded(context, x: 72, y: 54, width: 1296, height: 702, radius: 24, fill: color(0x0F172A), stroke: color(0x34435A), lineWidth: 2)
    rounded(context, x: 72, y: 54, width: 1296, height: 66, radius: 24, fill: color(0x152238))
    context.setFillColor(color(0xF87171).cgColor); context.fillEllipse(in: CGRect(x: 104, y: 80, width: 12, height: 12))
    context.setFillColor(color(0xFBBF24).cgColor); context.fillEllipse(in: CGRect(x: 128, y: 80, width: 12, height: 12))
    context.setFillColor(color(0x4ADE80).cgColor); context.fillEllipse(in: CGRect(x: 152, y: 80, width: 12, height: 12))
    text(context, "clu-governance  •  evidence-only preflight", x: 204, y: 74, size: 18, weight: .semibold, color: color(0xCBD5E1), monospaced: true)
    text(context, "CLU GOVERNANCE", x: 112, y: 158, size: 15, weight: .bold, color: color(0x5EEAD4), monospaced: true)
    divider(context, y: 194)

    switch scene {
    case .opening:
        text(context, "Evidence before a source change", x: 112, y: 238, size: 42, weight: .bold, color: color(0xF8FAFC))
        text(context, "Local policy • hashes • rollback readiness", x: 112, y: 300, size: 24, weight: .medium, color: color(0x94A3B8))
        rounded(context, x: 112, y: 376, width: 1118, height: 104, radius: 12, fill: color(0x12243A), stroke: color(0x245579), lineWidth: 1.5)
        text(context, "ALLOW", x: 146, y: 405, size: 21, weight: .bold, color: color(0x6EE7B7), monospaced: true)
        text(context, "is eligibility for separate approval — never authorization or application", x: 146, y: 442, size: 22, weight: .medium, color: color(0xE2E8F0))
        text(context, "Two real CLI evaluations follow.  No mutation is applied.", x: 112, y: 548, size: 21, weight: .medium, color: color(0x7DD3FC))
    case .allowCommand:
        text(context, "01  /  PERMITTED DOCUMENTATION PROPOSAL", x: 112, y: 236, size: 18, weight: .bold, color: color(0x6EE7B7), monospaced: true)
        text(context, "README.md • documented replacement • local policy check", x: 112, y: 274, size: 24, weight: .semibold, color: color(0xF8FAFC))
        rounded(context, x: 112, y: 334, width: 1118, height: 104, radius: 10, fill: color(0x08101D), stroke: color(0x263449), lineWidth: 1)
        text(context, "$ clu-governance agent-preflight --json < allow-request.json", x: 146, y: 370, size: 20, weight: .medium, color: color(0xE2E8F0), monospaced: true)
        text(context, "evaluating strict request envelope…", x: 146, y: 407, size: 18, weight: .regular, color: color(0x7DD3FC), monospaced: true)
        text(context, "Real CLI output is summarized on the next frame.", x: 112, y: 522, size: 20, weight: .medium, color: color(0x94A3B8))
    case .allowEvidence:
        text(context, "01  /  ALLOW — ELIGIBLE FOR SEPARATE APPROVAL", x: 112, y: 236, size: 18, weight: .bold, color: color(0x6EE7B7), monospaced: true)
        rounded(context, x: 112, y: 278, width: 1118, height: 330, radius: 12, fill: color(0x0D2A29), stroke: color(0x23856D), lineWidth: 1.5)
        let allowReason = (allow["reason_code"] as? String) ?? "eligible_for_human_approval"
        let lines = [
            ("decision", "allow", 0x6EE7B7),
            ("reason", allowReason, 0xE2E8F0),
            ("rollback_readiness_verified", bool(allow, "rollback_readiness_verified"), 0x7DD3FC),
            ("proposal_hash_verified", verifiedValue(allow, "proposal_hash_verified"), 0x7DD3FC),
            ("source_hash_verified", verifiedValue(allow, "source_hash_verified"), 0x7DD3FC),
            ("mutation_authorized", bool(allow, "mutation_authorized"), 0xFCD34D),
            ("mutation_applied", bool(allow, "mutation_applied"), 0xFCD34D),
        ]
        for (index, line) in lines.enumerated() {
            let y = CGFloat(316 + index * 38)
            text(context, line.0, x: 152, y: y, size: 19, weight: .semibold, color: color(0xA7F3D0), monospaced: true)
            text(context, ":  \(line.1)", x: 525, y: y, size: 19, weight: .medium, color: color(UInt32(line.2)), monospaced: true)
        }
        text(context, "Compact evidence summary from one real CLI JSON response", x: 112, y: 646, size: 16, weight: .medium, color: color(0x94A3B8))
    case .denyCommand:
        text(context, "02  /  DISALLOWED SOURCE DELETION", x: 112, y: 236, size: 18, weight: .bold, color: color(0xFCA5A5), monospaced: true)
        text(context, "clu/danger.py • delete operation • deny-by-default policy", x: 112, y: 274, size: 24, weight: .semibold, color: color(0xF8FAFC))
        rounded(context, x: 112, y: 334, width: 1118, height: 104, radius: 10, fill: color(0x08101D), stroke: color(0x263449), lineWidth: 1)
        text(context, "$ clu-governance agent-preflight --json < deny-request.json", x: 146, y: 370, size: 20, weight: .medium, color: color(0xE2E8F0), monospaced: true)
        text(context, "evaluating strict request envelope…", x: 146, y: 407, size: 18, weight: .regular, color: color(0x7DD3FC), monospaced: true)
        text(context, "A policy denial is evidence — it is not a mutation attempt.", x: 112, y: 522, size: 20, weight: .medium, color: color(0x94A3B8))
    case .denyEvidence:
        text(context, "02  /  DENY — TOOL ACTION BLOCKED", x: 112, y: 236, size: 18, weight: .bold, color: color(0xFCA5A5), monospaced: true)
        rounded(context, x: 112, y: 278, width: 1118, height: 264, radius: 12, fill: color(0x321C26), stroke: color(0xA94D61), lineWidth: 1.5)
        let blocker = (deny["exact_blocker"] as? String) ?? "delete_operation_denied"
        let lines = [
            ("decision", "deny", 0xFCA5A5),
            ("exact_blocker", blocker, 0xFCA5A5),
            ("eligible_for_human_approval", bool(deny, "eligible_for_human_approval"), 0xE2E8F0),
            ("mutation_authorized", bool(deny, "mutation_authorized"), 0xFCD34D),
            ("mutation_applied", bool(deny, "mutation_applied"), 0xFCD34D),
        ]
        for (index, line) in lines.enumerated() {
            let y = CGFloat(316 + index * 40)
            text(context, line.0, x: 152, y: y, size: 20, weight: .semibold, color: color(0xFECACA), monospaced: true)
            text(context, ":  \(line.1)", x: 525, y: y, size: 20, weight: .medium, color: color(UInt32(line.2)), monospaced: true)
        }
        text(context, "Configured integrations can stop the proposed tool action. CLU still applies nothing.", x: 112, y: 584, size: 18, weight: .medium, color: color(0x94A3B8))
    case .boundary:
        text(context, "THE BOUNDARY IS DELIBERATE", x: 112, y: 236, size: 18, weight: .bold, color: color(0x7DD3FC), monospaced: true)
        rounded(context, x: 112, y: 286, width: 1118, height: 246, radius: 12, fill: color(0x12243A), stroke: color(0x245579), lineWidth: 1.5)
        text(context, "ALLOW", x: 156, y: 326, size: 28, weight: .bold, color: color(0x6EE7B7), monospaced: true)
        text(context, "= eligible for separate approval", x: 350, y: 328, size: 25, weight: .semibold, color: color(0xF8FAFC))
        text(context, "DENY", x: 156, y: 390, size: 28, weight: .bold, color: color(0xFCA5A5), monospaced: true)
        text(context, "= proposed tool action blocked", x: 350, y: 392, size: 25, weight: .semibold, color: color(0xF8FAFC))
        divider(context, y: 452)
        text(context, "CLU applies neither change.", x: 156, y: 474, size: 27, weight: .bold, color: color(0xFCD34D))
        text(context, "Local-first  •  no daemon  •  no runtime network call  •  no default persistent state", x: 112, y: 590, size: 17, weight: .medium, color: color(0x94A3B8))
    }
    return context.makeImage()!
}

do {
    let evidence = try realEvidence(repositoryRoot: repositoryRoot)
    let scenes: [(Scene, Double)] = [(.opening, 1.8), (.allowCommand, 1.7), (.allowEvidence, 3.1), (.denyCommand, 1.7), (.denyEvidence, 3.0), (.boundary, 3.1)]
    let outputURL = URL(fileURLWithPath: output, relativeTo: URL(fileURLWithPath: repositoryRoot)).standardizedFileURL
    try FileManager.default.createDirectory(at: outputURL.deletingLastPathComponent(), withIntermediateDirectories: true)
    try? FileManager.default.removeItem(at: outputURL)
    guard let destination = CGImageDestinationCreateWithURL(outputURL as CFURL, UTType.gif.identifier as CFString, scenes.count, nil) else {
        throw NSError(domain: "readme-demo", code: 2, userInfo: [NSLocalizedDescriptionKey: "could not create GIF destination"])
    }
    CGImageDestinationSetProperties(destination, [kCGImagePropertyGIFDictionary: [kCGImagePropertyGIFLoopCount: 0]] as CFDictionary)
    let frameDirectoryURL = framesDirectory.map { URL(fileURLWithPath: $0, relativeTo: URL(fileURLWithPath: repositoryRoot)).standardizedFileURL }
    if let frameDirectoryURL {
        try? FileManager.default.removeItem(at: frameDirectoryURL)
        try FileManager.default.createDirectory(at: frameDirectoryURL, withIntermediateDirectories: true)
    }
    for (index, (scene, duration)) in scenes.enumerated() {
        let properties = [kCGImagePropertyGIFDictionary: [kCGImagePropertyGIFDelayTime: duration]] as CFDictionary
        let image = render(scene: scene, allow: evidence.allow, deny: evidence.deny)
        CGImageDestinationAddImage(destination, image, properties)
        if let frameDirectoryURL {
            let frameURL = frameDirectoryURL.appendingPathComponent(String(format: "%02d.png", index + 1))
            guard let frameDestination = CGImageDestinationCreateWithURL(frameURL as CFURL, UTType.png.identifier as CFString, 1, nil) else {
                throw NSError(domain: "readme-demo", code: 4, userInfo: [NSLocalizedDescriptionKey: "could not create PNG frame"])
            }
            CGImageDestinationAddImage(frameDestination, image, nil)
            guard CGImageDestinationFinalize(frameDestination) else {
                throw NSError(domain: "readme-demo", code: 5, userInfo: [NSLocalizedDescriptionKey: "could not finalize PNG frame"])
            }
        }
    }
    guard CGImageDestinationFinalize(destination) else {
        throw NSError(domain: "readme-demo", code: 3, userInfo: [NSLocalizedDescriptionKey: "could not finalize GIF"])
    }
    print("wrote \(outputURL.path) from real agent-preflight CLI output")
} catch {
    fputs("generate_policy_evidence_demo: \(error.localizedDescription)\n", stderr)
    exit(1)
}
