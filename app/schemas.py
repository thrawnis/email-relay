"""Request models."""
from __future__ import annotations

import base64
import binascii
import re

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator


def _as_list(v):
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    return v


class Attachment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filename: str = Field(min_length=1, max_length=255)
    content: str = Field(description="Base64-encoded file content")
    content_type: str | None = Field(default=None, max_length=255)

    @field_validator("filename")
    @classmethod
    def _safe_filename(cls, v: str) -> str:
        if re.search(r"[\r\n/\\]", v):
            raise ValueError("filename must not contain path separators or newlines")
        return v

    @field_validator("content_type")
    @classmethod
    def _ctype(cls, v):
        if v is not None and not re.fullmatch(r"[\w.+-]+/[\w.+-]+", v):
            raise ValueError("content_type must look like type/subtype")
        return v

    def decoded_size(self) -> int:
        try:
            return len(base64.b64decode(self.content, validate=True))
        except (binascii.Error, ValueError) as e:
            raise ValueError(f"attachment {self.filename!r} is not valid base64") from e


class SendRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    to: list[EmailStr]
    cc: list[EmailStr] = []
    bcc: list[EmailStr] = []
    subject: str = Field(min_length=1, max_length=998)
    text: str | None = None
    html: str | None = None
    from_: EmailStr | None = Field(default=None, alias="from")
    from_name: str | None = Field(default=None, max_length=200)
    reply_to: EmailStr | None = None
    attachments: list[Attachment] = []

    @field_validator("to", "cc", "bcc", mode="before")
    @classmethod
    def _listify(cls, v):
        return _as_list(v)

    @field_validator("subject", "from_name")
    @classmethod
    def _no_newlines(cls, v):
        if v is not None and re.search(r"[\r\n]", v):
            raise ValueError("must not contain newlines")
        return v

    @model_validator(mode="after")
    def _check(self):
        if not self.to:
            raise ValueError("'to' must contain at least one address")
        if not (self.text or self.html):
            raise ValueError("provide 'text' and/or 'html'")
        return self

    def all_recipients(self) -> list[str]:
        return [*self.to, *self.cc, *self.bcc]

    def to_payload(self) -> dict:
        """JSON-safe dict persisted on the queue and handed to the backend."""
        return {
            "to": list(self.to), "cc": list(self.cc), "bcc": list(self.bcc),
            "subject": self.subject, "text": self.text, "html": self.html,
            "from_name": self.from_name, "reply_to": self.reply_to,
            "attachments": [a.model_dump() for a in self.attachments],
        }


class KeyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    rate_per_minute: int | None = Field(default=None, ge=1)
    rate_per_day: int | None = Field(default=None, ge=1)
    allowed_from: list[str] = []
    notes: str | None = Field(default=None, max_length=1000)
    # Lets this key log in on the UNENCRYPTED SMTP port (its key and mail then cross the network in clear text)
    allow_plaintext_smtp: bool = False

    @field_validator("allowed_from")
    @classmethod
    def _patterns(cls, v: list[str]) -> list[str]:
        out = []
        for p in v:
            p = p.strip().lower()
            if not p:
                continue
            if not re.fullmatch(r"(\*|[^@\s*]+)@[^@\s*]+\.[^@\s*]+", p):
                raise ValueError(f"invalid allowed_from entry {p!r} (use user@domain or *@domain)")
            out.append(p)
        return out


class KeyUpdate(KeyCreate):
    name: str | None = Field(default=None, min_length=1, max_length=100)
