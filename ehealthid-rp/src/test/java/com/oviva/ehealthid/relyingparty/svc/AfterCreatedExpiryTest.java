package com.oviva.ehealthid.relyingparty.svc;

import static org.junit.jupiter.api.Assertions.*;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class AfterCreatedExpiryTest {

  @Test
  void afterCreate() {

    var ttl = 12345L;
    var sut = new AfterCreatedExpiry(ttl);

    // when
    var expiry = sut.expireAfterCreate(null, null, 123L);

    // then
    assertEquals(ttl, expiry);
  }

  @Test
  void afterUpdate_keepsRemainingDuration() {

    var ttl = 12345L;
    var sut = new AfterCreatedExpiry(ttl);

    // when
    var remaining = 1000L;
    var expiry = sut.expireAfterUpdate(null, null, 39391L, remaining);

    // then
    assertEquals(remaining, expiry);
  }

  @Test
  void afterRead_keepsRemainingDuration() {

    var ttl = 12345L;
    var sut = new AfterCreatedExpiry(ttl);

    // when
    var remaining = 1290L;
    var expiry = sut.expireAfterRead(null, null, 39391L, remaining);

    // then
    assertEquals(remaining, expiry);
  }

  @Test
  void cache_readAndUpdateDoNotShortenOrExtendLifetime() {

    var ttl = Duration.ofMinutes(20);
    var now = new AtomicLong(0);
    Cache<String, String> cache =
        Caffeine.newBuilder()
            .ticker(now::get)
            .executor(Runnable::run)
            .expireAfter(new AfterCreatedExpiry<String>(ttl.toNanos()))
            .build();

    // auth: session created
    cache.put("s", "v1");

    // select-idp: load at +7s, save at +8s
    now.set(Duration.ofSeconds(7).toNanos());
    assertNotNull(cache.getIfPresent("s"));
    now.set(Duration.ofSeconds(8).toNanos());
    cache.put("s", "v2");

    // callback: load at +9s
    now.set(Duration.ofSeconds(9).toNanos());
    assertNotNull(cache.getIfPresent("s"));

    // relay arrives at +27s
    now.set(Duration.ofSeconds(27).toNanos());
    assertEquals("v2", cache.getIfPresent("s"));
    assertTrue(cache.asMap().containsKey("s"));

    // still there just before the ttl, measured from creation
    now.set(ttl.minusSeconds(1).toNanos());
    assertNotNull(cache.getIfPresent("s"));

    // gone after the ttl, measured from creation
    now.set(ttl.plusSeconds(1).toNanos());
    assertNull(cache.getIfPresent("s"));
  }
}
