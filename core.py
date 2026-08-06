"""Validated API contracts for the ShadowGlass v35 private-cluster runtime."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


SERVICE_NAME = "shadowglass-v35"
VERSION = "9.0.0-forge"
COUNTY_RE = re.compile(r"^[A-Za-z][A-Za-z .'-]{0,79}$")
INSTRUMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 &/().,'-]{0,119}$")
IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9_.:-]{8,160}$")


def _clean_county(value: str) -> str:
    cleaned = " ".join(value.split())
    if not COUNTY_RE.fullmatch(cleaned):
        raise ValueError("invalid county")
    return cleaned


def _clean_instrument(value: str) -> str:
    cleaned = " ".join(value.split())
    if not INSTRUMENT_RE.fullmatch(cleaned):
        raise ValueError("invalid instrument type")
    return cleaned


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ScrapeRequest(StrictModel):
    county: str
    instrumentType: str
    startPage: int = Field(default=0, ge=0, le=1_000_000)

    @field_validator("county")
    @classmethod
    def validate_county(cls, value: str) -> str:
        return _clean_county(value)

    @field_validator("instrumentType")
    @classmethod
    def validate_instrument(cls, value: str) -> str:
        return _clean_instrument(value)

    def queue_payload(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "action": "scrape",
            "county": self.county,
            "instrument_type": self.instrumentType,
            "start_page": self.startPage,
        }


class ScrapeAllRequest(StrictModel):
    county: str

    @field_validator("county")
    @classmethod
    def validate_county(cls, value: str) -> str:
        return _clean_county(value)


class ScrapeMultiRequest(StrictModel):
    counties: list[str] = Field(min_length=1, max_length=25)

    @field_validator("counties")
    @classmethod
    def validate_counties(cls, values: list[str]) -> list[str]:
        cleaned = [_clean_county(value) for value in values]
        if len({value.casefold() for value in cleaned}) != len(cleaned):
            raise ValueError("duplicate county")
        return cleaned


class DiscoverRequest(StrictModel):
    county: str

    @field_validator("county")
    @classmethod
    def validate_county(cls, value: str) -> str:
        return _clean_county(value)


class DirectScrapeRequest(StrictModel):
    county: str
    instrumentType: str
    pages: int = Field(default=1, ge=1, le=50)

    @field_validator("county")
    @classmethod
    def validate_county(cls, value: str) -> str:
        return _clean_county(value)

    @field_validator("instrumentType")
    @classmethod
    def validate_instrument(cls, value: str) -> str:
        return _clean_instrument(value)

    def queue_payload(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "action": "scrape",
            "county": self.county,
            "instrument_type": self.instrumentType,
            "start_page": 0,
            "end_page": self.pages - 1,
            "priority_mode": "direct",
        }


def validate_idempotency_key(value: str | None) -> str:
    if not value or not IDEMPOTENCY_RE.fullmatch(value):
        raise ValueError("a valid X-Idempotency-Key header is required")
    return value
