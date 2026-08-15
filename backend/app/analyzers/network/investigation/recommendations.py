from __future__ import annotations

from app.schemas.network import InvestigationTarget


def recommendations_for(target: InvestigationTarget) -> list[str]:
    actions = ["Apply the supplied display filter in Wireshark."] if target.wireshark_filter else []
    categories = {reason.category for reason in target.suspicion.reasons}
    if target.target_type == "tcp_stream":
        actions.extend(["Select a packet and use Follow -> TCP Stream.", "Inspect the ASCII view first, then switch to Raw or Hex if bytes are hidden or non-printable."])
    elif target.target_type == "udp_stream":
        actions.append("Review the UDP datagrams chronologically and compare both headers and payloads.")
    elif target.target_type == "dns_group":
        actions.extend(["Expand Domain Name System -> Queries -> Name.", "Compare the changing subdomain labels chronologically; concatenate only the labels identified by the evidence."])
    elif target.target_type == "http_activity":
        actions.append("Inspect request methods, URIs, headers, and bodies in chronological order.")
        if "file-magic" in categories or "file-transfer" in categories:
            actions.append("Use File -> Export Objects -> HTTP and verify the exported object's hash and magic bytes.")
    elif target.target_type == "artifact":
        actions.append("Return to the packet or stream that transferred this object and verify its content type against its magic bytes.")
    elif target.target_type == "packet_group":
        actions.append("Sort the filtered frames chronologically and compare constant fields with the changing fields listed below.")
    elif target.target_type == "packet":
        actions.append("Open the frame details and inspect the highlighted header fields and packet bytes.")
    elif target.target_type == "conversation":
        actions.append("Inspect both traffic directions and then follow each listed stream separately.")

    if "encoded" in categories:
        actions.append("Locate the encoded-looking region described by CTFKit; copy only that region before attempting the named decoding.")
    if "payload-entropy" in categories:
        actions.append("Use Raw or Hex representation because an ASCII rendering may hide high-entropy or compressed bytes.")
    if "covert-channel" in categories or "field-variation" in categories:
        changing = next((reason.evidence.get("changing_fields") for reason in target.suspicion.reasons if reason.category == "field-variation"), None)
        suffix = f" ({', '.join(str(value) for value in changing)})" if isinstance(changing, list) else ""
        actions.append(f"Compare packet header values, not only payload bytes{suffix}; treat the proposed transformation as a hypothesis until reproduced.")
    if "credential" in categories or "command" in categories:
        actions.append("Follow the conversation and verify the command or credential exchange in both directions.")
    if target.interesting_frames:
        frames = ", ".join(str(item.frame_number) for item in target.interesting_frames[:8])
        actions.append(f"Pay particular attention to frames {frames}; their measurable differences are listed in the target evidence.")
    return list(dict.fromkeys(actions))
