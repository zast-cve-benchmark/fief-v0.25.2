---
id: "GHSA-hj8m-9fhf-v7jp"
category: "ssti"
severity: "high"
cwe_ids: ["CWE-1336"]
refs:
  - url: "https://github.com/fief-dev/fief/security/advisories/GHSA-hj8m-9fhf-v7jp"
    type: ADVISORY
    conclusion: |-
      fief-server Server-Side Template Injection (SSTI) vulnerability: user input is improperly embedded into a template and can execute code server-side (CWE-1336). Affects fief-server 0.19.0 through 0.25.2 (PyPI ecosystem), fixed in 0.25.3 (commit 91e56625b641fa419e2985772266774bae18382b). Advisory reproduction steps: inject `{{ cycler.__init__.__globals__.os.popen('id').read() }}` into the Edit Base template of an email template to execute server-side. CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H, database_specific.severity is CRITICAL.
  - url: "https://github.com/fief-dev/fief/commit/91e56625b641fa419e2985772266774bae18382b"
    type: WEB
    conclusion: |-
      Fix commit 91e56625b641fa419e2985772266774bae18382b (corresponding to release 0.25.3, https://github.com/fief-dev/fief/releases/tag/v0.25.3).
---

# Server-Side Template Injection — PATCH /admin/api/email-templates/{id}

## Vulnerability Description

In fief-server's PATCH /admin/api/email-templates/{id}, the request-body `subject` field is written verbatim onto the EmailTemplate ORM row via setattr and committed to the workspace database with no allowlist or validation; on a later email dispatch the background worker task (fief/tasks/register.py and fief/tasks/forgot_password.py) loads that stored string and executes it in EmailSubjectRenderer.render() through a plain jinja2.Environment that is not a sandbox, so Jinja expressions embedded in the email subject reach arbitrary code execution on the worker. The renderer is a stock jinja2.Environment, not an ImmutableSandboxedEnvironment, and autoescape only escapes rendered output without restricting template logic.

## Impact Scope

- Endpoint: `PATCH /admin/api/email-templates/{id}`

## Audit Trail

1. `fief/apps/api/routers/email_templates.py:69` — The `subject` value from the request body is setattr'd onto the EmailTemplate with no allowlist or validation, so the attacker controls the subject template source string.

   ```python
   for field, value in email_template_update_dict.items():
   ```
2. `fief/apps/api/routers/email_templates.py:72` — repository.update commits the attacker-controlled subject string into the workspace database, persisting it for a later render.

   ```python
   await repository.update(email_template)
   ```
3. `fief/services/email_template/renderers.py:124` — The stored subject is loaded and executed via subject_template_object.render(context.dict()), so Jinja expressions inside the attacker subject are evaluated.

   ```python
   subject_template_object = jinja_environment.get_template(type.value)
   return subject_template_object.render(context.dict())
   ```
4. `fief/services/email_template/renderers.py:135` — The environment the subject runs in is a plain jinja2.Environment, not a sandbox, so the attacker's Jinja expressions reach arbitrary code execution in the worker that sends the email.

   ```python
   self._jinja_environment = jinja2.Environment(loader=loader, autoescape=True)
   ```

## Evidence Code

```python
// fief/apps/api/routers/email_templates.py#L58C1-L80C73
async def update_email_template(
    email_template_update: schemas.email_template.EmailTemplateUpdate,
    email_template: EmailTemplate = Depends(get_email_template_by_id_or_404),
    repository: EmailTemplateRepository = Depends(
        get_workspace_repository(EmailTemplateRepository)
    ),
    audit_logger: AuditLogger = Depends(get_audit_logger),
    trigger_webhooks: TriggerWebhooks = Depends(get_trigger_webhooks),
) -> schemas.email_template.EmailTemplate:
    email_template_update_dict = email_template_update.dict(exclude_unset=True)

    for field, value in email_template_update_dict.items():
        setattr(email_template, field, value)

    await repository.update(email_template)
    audit_logger.log_object_write(AuditLogMessage.OBJECT_UPDATED, email_template)
    trigger_webhooks(
        EmailTemplateUpdated,
        email_template,
        schemas.email_template.EmailTemplate,
    )

    return schemas.email_template.EmailTemplate.from_orm(email_template)
```

```python
// fief/services/email_template/renderers.py#L122C5-L125C62
    async def render(self, type, context: "EmailContext") -> str:
        jinja_environment = await self._get_jinja_environment()
        subject_template_object = jinja_environment.get_template(type.value)
        return subject_template_object.render(context.dict())
```

```python
// fief/services/email_template/renderers.py#L127C5-L136C39
    async def _get_jinja_environment(self) -> jinja2.Environment:
        if self._jinja_environment is None:
            templates = await self.repository.all()
            loader = jinja2.FunctionLoader(
                EmailSubjectLoader(
                    templates, templates_overrides=self.templates_overrides
                )
            )
            self._jinja_environment = jinja2.Environment(loader=loader, autoescape=True)
        return self._jinja_environment
```

## Root Cause

`injection` — `fief/services/email_template/renderers.py:135`

## Exploitation Steps

Set subject to {{ cycler.__init__.__globals__.os.popen('id').read() }} via an authorized admin API key, then trigger any welcome/forgot-password email of that template type to execute it.
