
source [find mem_helper.tcl]

if { [info exists TRACE_HZ] } {
   set _TRACE_HZ $TRACE_HZ
} else {
   set _TRACE_HZ 32000000
}


proc kstim { stim } {
    puts "KKK: enabling stimulus: $stim"
    # DBG_DEMCR |= TRCENA
    mmw 0xE000EDFC [expr (1<<24)] 0

    # DBGMCR_CR |= TRACE_IOEN, DEBUG_STOP, DEBUG_STANDBY, DEBUG_SLEEP 
    mmw 0xe0042004 [expr ((1<<5) | 0x7)] 0

    # ST ref man says we set this to 1 even in async mode, it's still "one" pin wide
    # TPIU_CSPSR = 1
    mww 0xe0040004 1

    # set TPIU_ACPR 
    # FIXME - need this loaded in somehow.
    set prescaler [expr ($TRACE_HZ / 2000000) - 1]
    #set prescaler [expr (32000000 / 2000000) - 1]
    mww 0xE0040010 $prescaler

    # <<<< SWOPY tells stlink to stop/start trace here

    # SPPR = NRZ, should have already been done by oocd,
    # as that's stlink specific
    
    # TPIU_FFCR = 0, (oocd was using bit 8, for triggers?)
    mww 0xE0040304 0

    # Unlock ITM
    mww 0xe0000fb0 0xC5ACCE55
    # use ATB ID #1, tpiu sync, enable ITM (ITM_TCR)
    mww 0xe0000e80 [expr (1<<16) | (1<<2) | (1 << 0)]
    # We wish to use all stimulus ports in user code (ITM_TPR = 0xf)
    mww 0xe0000e40 0xf
    # turn on stim ports of desire (ITM_TER = $stim)
    mww 0xe0000e00 $stim


    # TODO - this should be a parameter? Should setup tap sync bits here 
    # DWT_CTRL = syncbits | cyccnt
    mmw 0xE0001000 [expr ((2 << 10) | 1)] [expr (3<<10)]
}

proc rstim { } {
    # Unlock ITM
    mww 0xe0000fb0 0xC5ACCE55
    # Read stimulus (ITM_TER)
    mdw 0xe0000e00
}

add_help_text kstim "Enable ITM Trace for given Stimulus ports"
add_help_text rstim "Read the currently enabled ITM Stimulus ports"


