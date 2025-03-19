package com.linkmoa.domain.member.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Provider {

    GOOGLE("google"), KAKAO("kakao");

    private final String providerId;

    public boolean equals(String providerId) {
        return this.providerId.equals(providerId);
    }

    public static Provider from(String providerId) {
        for (Provider provider : Provider.values()) {
            if (provider.getProviderId().equals(providerId)) {
                return provider;
            }
        }
        throw new IllegalArgumentException("Illegal provider ID: " + providerId);
    }
}
