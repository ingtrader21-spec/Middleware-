# Agent Workspace User Guide

When a TEST_SYN call rings, one call workspace opens with customer identity on the left, lifecycle and notes in the center, and history/follow-up on the right.

1. Confirm the direction, number, campaign, extension and match status in the header.
2. If matching is ambiguous, do not select a customer without verification. Open the relevant CRM candidate when authorized.
3. Enter notes normally. Autosave status changes from dirty to saving to saved. On a temporary failure, keep the tab open; the session draft is restored after refresh and retried after recovery.
4. Use campaign quick phrases as inserts; free-form text remains editable.
5. After the call ends, choose a disposition and any required sub-disposition. Required notes or callbacks are enforced by the server.
6. Schedule callbacks and follow-up tasks. This records work in Odoo; it does not automatically dial or send a message.
7. SMS and email remain disabled until separately authorized.

If realtime shows reconnecting, wait for recovery. Refreshing is safe: the current call, context and notes reload without a second popup. If a duplicate-tab warning appears, close the secondary tab and continue in the primary workspace.

Keyboard users can tab through navigation, CRM links, notes, templates, disposition and callback controls. Visible focus identifies the active control. Status and error messages use live regions.
