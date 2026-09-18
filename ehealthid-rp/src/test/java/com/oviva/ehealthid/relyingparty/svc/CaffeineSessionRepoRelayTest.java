package com.oviva.ehealthid.relyingparty.svc;

import static org.junit.jupiter.api.Assertions.*;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.oviva.ehealthid.relyingparty.svc.SessionRepo.Session;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class CaffeineSessionRepoRelayTest {

  private static CaffeineSessionRepo repo(Duration ttl) {
    return new CaffeineSessionRepo(Caffeine.newBuilder().<String, Session>build(), ttl);
  }

  @Test
  void findByUpstreamState_matchesOnlyExactState() {
    var sut = repo(Duration.ofMinutes(5));
    sut.save(Session.create().id("a").upstreamState("state-a").build());
    sut.save(Session.create().id("b").upstreamState("state-b").build());
    sut.save(Session.create().id("c").build());

    assertEquals("a", sut.findByUpstreamState("state-a").id());
    assertEquals("b", sut.findByUpstreamState("state-b").id());
    assertNull(sut.findByUpstreamState("state-"));
    assertNull(sut.findByUpstreamState("state-a "));
    assertNull(sut.findByUpstreamState(""));
    assertNull(sut.findByUpstreamState(" "));
  }

  @Test
  void findByUpstreamState_ignoresExpiredAndRemovedSessions() {
    var sut = repo(Duration.ofMinutes(5));
    sut.save(
        Session.create()
            .id("old")
            .createdAt(Instant.now().minus(Duration.ofMinutes(6)))
            .upstreamState("old-state")
            .build());
    sut.save(Session.create().id("gone").upstreamState("gone-state").build());
    sut.remove("gone");

    assertNull(sut.findByUpstreamState("old-state"));
    assertNull(sut.findByUpstreamState("gone-state"));
  }

  @Test
  void legacyConstructorHasNoRelayState() {
    var session = new Session("id", null, null, null, null, null, null, null, null);
    assertNull(session.upstreamState());
    assertNull(session.relayedIdToken());
    assertNull(session.toBuilder().build().upstreamState());
  }
}
