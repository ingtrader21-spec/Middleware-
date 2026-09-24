# Human approval

CRM and voice commands return proposals only. Middleware stores immutable proposal hashes and a pending approval. Only authorized approver roles may approve or reject. Approval records do not dispatch actions in this release. Odoo writes, VICIdial commands, messages, callbacks, and workflow activation remain disabled.
