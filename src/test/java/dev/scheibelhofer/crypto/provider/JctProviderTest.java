package dev.scheibelhofer.crypto.provider;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class JctProviderTest {
    
    @Test
    public void testGetInstance() throws Exception {
        JctProvider prov1 = JctProvider.getInstance();
        assertNotNull(prov1);
        JctProvider prov2 = JctProvider.getInstance();
        assertTrue(prov1 == prov2);
    }
}
