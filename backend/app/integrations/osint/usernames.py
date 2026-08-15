from __future__ import annotations

import time
from urllib.parse import quote

import httpx

from app.integrations.osint.base import (
    AdapterOutput,
    bounded_json,
    clean_error,
    elapsed_ms,
)


class UsernameAdapter:
    name = "usernames"
    platform: str
    api_url: str
    profile_template: str

    async def collect(self, username: str, client: httpx.AsyncClient) -> AdapterOutput:
        started = time.monotonic()
        profile_url = self.profile_template.format(username=quote(username, safe=""))
        try:
            response, payload = await bounded_json(
                client,
                self.api_url.format(username=quote(username, safe="")),
                headers={"User-Agent": "CTFKit-OSINT/0.1"},
                maximum_bytes=512 * 1024,
            )
            record = self.parse(username, profile_url, response, payload)
            return AdapterOutput(
                f"usernames:{self.platform.lower()}",
                self.api_url.split("{", 1)[0],
                [record],
                "success" if record["exists"] is True else "no_data",
                duration_ms=elapsed_ms(started),
            )
        except Exception as exc:
            return AdapterOutput(
                f"usernames:{self.platform.lower()}",
                self.api_url.split("{", 1)[0],
                status="error",
                error=clean_error(exc),
                duration_ms=elapsed_ms(started),
            )

    def parse(
        self, username: str, profile_url: str, response: httpx.Response, payload: object
    ) -> dict[str, object]:
        raise NotImplementedError


class GitHubUsernameAdapter(UsernameAdapter):
    platform = "GitHub"
    api_url = "https://api.github.com/users/{username}"
    profile_template = "https://github.com/{username}"

    def parse(
        self, username: str, profile_url: str, response: httpx.Response, payload: object
    ) -> dict[str, object]:
        if response.status_code == 404:
            return _missing(self.platform, username, profile_url)
        response.raise_for_status()
        data = payload if isinstance(payload, dict) else {}
        return _profile(
            self.platform,
            username,
            str(data.get("html_url") or profile_url),
            data.get("name"),
            data.get("bio"),
            {
                "public_repos": data.get("public_repos"),
                "followers": data.get("followers"),
                "created_at": data.get("created_at"),
            },
        )


class GitLabUsernameAdapter(UsernameAdapter):
    platform = "GitLab"
    api_url = "https://gitlab.com/api/v4/users?username={username}"
    profile_template = "https://gitlab.com/{username}"

    def parse(
        self, username: str, profile_url: str, response: httpx.Response, payload: object
    ) -> dict[str, object]:
        response.raise_for_status()
        users = payload if isinstance(payload, list) else []
        exact = next(
            (
                item
                for item in users
                if isinstance(item, dict)
                and str(item.get("username", "")).lower() == username.lower()
            ),
            None,
        )
        if exact is None:
            return _missing(self.platform, username, profile_url)
        return _profile(
            self.platform,
            username,
            str(exact.get("web_url") or profile_url),
            exact.get("name"),
            exact.get("bio"),
            {"state": exact.get("state")},
        )


class RedditUsernameAdapter(UsernameAdapter):
    platform = "Reddit"
    api_url = "https://www.reddit.com/user/{username}/about.json"
    profile_template = "https://www.reddit.com/user/{username}/"

    def parse(
        self, username: str, profile_url: str, response: httpx.Response, payload: object
    ) -> dict[str, object]:
        if response.status_code == 404:
            return _missing(self.platform, username, profile_url)
        response.raise_for_status()
        wrapper = payload if isinstance(payload, dict) else {}
        data = wrapper.get("data", {}) if isinstance(wrapper.get("data"), dict) else {}
        return _profile(
            self.platform,
            username,
            profile_url,
            data.get("subreddit", {}).get("title")
            if isinstance(data.get("subreddit"), dict)
            else None,
            None,
            {
                "created_utc": data.get("created_utc"),
                "link_karma": data.get("link_karma"),
                "comment_karma": data.get("comment_karma"),
            },
        )


class HackerNewsUsernameAdapter(UsernameAdapter):
    platform = "Hacker News"
    api_url = "https://hacker-news.firebaseio.com/v0/user/{username}.json"
    profile_template = "https://news.ycombinator.com/user?id={username}"

    def parse(
        self, username: str, profile_url: str, response: httpx.Response, payload: object
    ) -> dict[str, object]:
        response.raise_for_status()
        if not isinstance(payload, dict):
            return _missing(self.platform, username, profile_url)
        return _profile(
            self.platform,
            username,
            profile_url,
            payload.get("id"),
            payload.get("about"),
            {"created": payload.get("created"), "karma": payload.get("karma")},
        )


def _missing(platform: str, username: str, profile_url: str) -> dict[str, object]:
    return {
        "platform": platform,
        "username": username,
        "exists": False,
        "profile_url": profile_url,
        "attributes": {},
    }


def _profile(
    platform: str,
    username: str,
    profile_url: str,
    display_name: object,
    bio: object,
    attributes: dict[str, object],
) -> dict[str, object]:
    return {
        "platform": platform,
        "username": username,
        "exists": True,
        "profile_url": profile_url,
        "display_name": str(display_name)[:300] if display_name else None,
        "bio": str(bio)[:1_000] if bio else None,
        "attributes": {
            key: value for key, value in attributes.items() if value is not None
        },
    }


def default_username_adapters() -> list[UsernameAdapter]:
    return [
        GitHubUsernameAdapter(),
        GitLabUsernameAdapter(),
        RedditUsernameAdapter(),
        HackerNewsUsernameAdapter(),
    ]
