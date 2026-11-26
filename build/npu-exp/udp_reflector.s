; UDP reflector, hooked at PC 5047 (after the ingress template) with `call reflector`.
; IPv4/UDP to port 7777 (untagged, 20-byte IP header) is swapped and sent straight
; back out of the ingress port, never reaching the CPU. Anything else continues.
; Packet bytes are addressed from h1 (= r6[8:0], Ethernet header start).
;   h1+0  dst MAC   h1+6  src MAC   h1+12 EtherType
;   h1+22 TTL, proto, IP checksum   h1+26 src IP   h1+30 dst IP
;   h1+34 src port  h1+36 dst port
reflector:
    clr r0[15:0]                    ; the hooked stock instruction
    [!r8.27] br pass                ; not IPv4
    [!r8.23] br pass                ; not UDP
    b.ne r14[6:0], 0x22, pass       ; L4 offset must be 34
    ld r20[15:0], h1+36
    nop
    b.ne r20[15:0], 0x1e61, pass    ; dst port 7777
; swap MAC addresses (6 bytes each, as 2 + 4)
    ld r20[15:0], h1+0
    ld r21, h1+2
    ld r22[15:0], h1+6
    ld r23, h1+8
    nop
    st h1+0, r22[15:0]
    st h1+2, r23
    st h1+6, r20[15:0]
    st h1+8, r21
; swap IP addresses
    ld r24, h1+26
    ld r25, h1+30
    nop
    st h1+26, r25
    st h1+30, r24
; swap UDP ports (the UDP checksum is unchanged by both swaps)
    ld r26[15:0], h1+34
    ld r27[15:0], h1+36
    nop
    st h1+34, r27[15:0]
    st h1+36, r26[15:0]
; TTL - 1 with an incremental IPv4 header checksum update (RFC 1624)
    ld r28, h1+22                   ; r28 = TTL:proto:checksum
    nop
    mov.x r29[31:16], r28[31:16]    ; old TTL:proto
    nop
    mov r29[15:0], r28[31:16]
    nop
    subi r29[15:8], r29[15:8], 0x1  ; new TTL:proto
    nop
    csum r28[15:0], r28[15:0], r29[31:16], r29[15:0]
    nop
    mov r28[31:16], r29[15:0]
    nop
    st h1+22, r28
; egress: back out of the ingress port, not to a CPU queue
    ld r30, h3+20
    nop
    mov r30[7:2], r4[5:0]           ; out port = in_port
    nop
    st h3+20, r30
    ld r31, h3+8
    nop
    movi r31[15:7], 0x0             ; queue 0 (0x194 would be the CPU)
    nop
    st h3+8, r31
    send
pass:
    ret
