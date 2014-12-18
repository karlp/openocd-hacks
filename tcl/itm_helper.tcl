
source [find mem_helper.tcl]

# this doesn't work
if { [info exists TRACE_HZ] } {
   set _TRACE_HZ $TRACE_HZ
} else {
   set _TRACE_HZ 32000000
}


proc hack_enable_trace { } {
	puts "enabling trace itself"
    # DBG_DEMCR |= TRCENA
    mmw 0xE000EDFC [expr (1<<24)] 0

    # DBGMCR_CR |= TRACE_IOEN, DEBUG_STOP, DEBUG_STANDBY, DEBUG_SLEEP 
    mmw 0xe0042004 [expr ((1<<5) | 0x7)] 0

    # ST ref man says we set this to 1 even in async mode, it's still "one" pin wide
    # TPIU_CSPSR = 1
    mww 0xe0040004 1

    # set TPIU_ACPR 
    # FIXME - need this loaded in somehow.
    #set prescaler [expr ($TRACE_HZ / 2000000) - 1]
    set prescaler [expr (24000000 / 2000000) - 1]
    set prescaler [expr (32000000 / 2000000) - 1]
    mww 0xE0040010 $prescaler

    # <<<< SWOPY tells stlink to stop/start trace here

    # SPPR = NRZ, should have already been done by oocd,
    # as that's stlink specific
}

proc kprof { } {
	puts "KKK: profile on"
	hack_enable_trace

    # TPIU_FFCR = 0, (oocd was using bit 8, for triggers?)
    mww 0xE0040304 0
    # Unlock ITM
    mww 0xe0000fb0 0xC5ACCE55
    # use ATB ID #1, txena (from dwt), tpiu sync, enable ITM (ITM_TCR)
    mww 0xe0000e80 [expr (1<<16) | (1<<3) | (1<<2) | (1 << 0)]
    # We wish to use all stimulus ports in user code (ITM_TPR = 0xf)


	# docs say need two writes...
	# DWT_CTRL = POSTINIT(x7) postrset x7, cyccntent
	# (cyntap is bit 9, chooses whether postcnt goes on cyctap 6 or 10)
	#
	# pcsamplena, sync=1, cyctap, postreset=0xf, cyccntena
	#mww 0xe0001000 [expr ((1<<12) | (1<<10) | (1<<9) | (0xf<<1) | 1)]
	#pcsamplena, postreset=0xf, cyccntena
	#mww 0xe0001000 [expr ((0<<12) | 1)]
	mww 0xe0001000 [expr ((1<<12) | (1<<10) | (0<<9)|(0xf<<1) | 1)]
	#mww 0xe0001000 [expr ((0<<22) | (1<<10)| (0<<9)|(2<<1) | 1)]
	#mww 0xe0001000 [expr ((1<<22) | (1<<10)| (0<<9)|(2<<1) | 1)]

	#DWT_CTRL = pc sample ena | syncbits(2) | cyccntena & syncbits mask
	#mmw 0xe0001000 [expr ((1<<12) | (2<<10) | 1)] [expr (3<<10)]
}
    
proc kstim { stim } {
    puts "KKK: enabling stim: $stim"
	hack_enable_trace

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
add_help_text kprof "enable profilign"


