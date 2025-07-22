// Copyright zeroRISC Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
// smoke test vseq to walk through DAI states and request keys

// `define PART_CONTENT_RANGE(i) \
//     {[PART_BASE_ADDRS[``i``]: PART_OTP_SPECIALS_OFFSETS[``i``] - 1]}

// Digest fields can be zeroized, but the zeroization field should be written to only when the
// partition is designated to be zeroized.
// The last 8 bytes or any partition is the zeroizible field, hence ignore it when generating legal
// addresses to zeroize.
`define PART_CONTENT_RANGE(i) \
    {[PartInfo[``i``].offset: PartInfo[``i``+1].offset - 9]}

class otp_ctrl_zeroization_vseq extends otp_ctrl_smoke_vseq;
  `uvm_object_utils(otp_ctrl_zeroization_vseq)
  `uvm_object_new


  rand bit set_dai_regwen;
  rand bit enable_trigger_checks;

  constraint regwens_c {
    set_dai_regwen dist {0 :/ 8, 1 :/ 2};
  }

  constraint trigger_checks_c {
    // enable_trigger_checks dist {0 :/ 4, 1 :/ 6};
    enable_trigger_checks == 0;
  }

  constraint num_trans_c {
    num_trans  == 1;
    num_dai_op inside {[1:10]};
  }

  constraint partition_index_c {
    part_idx inside {
      VendorTestIdx,
      CreatorSwCfgIdx,
      OwnerSwCfgIdx,
      RotCreatorAuthCodesignIdx,
      RotCreatorAuthStateIdx,
      HwCfg0Idx,
      HwCfg1Idx,
      Secret0Idx,
      Secret1Idx,
      Secret2Idx
    };
  }

  constraint dai_wr_legal_addr_c {
    if (part_idx == VendorTestIdx)
        dai_addr inside `PART_CONTENT_RANGE(VendorTestIdx);
    if (part_idx == CreatorSwCfgIdx)
        dai_addr inside `PART_CONTENT_RANGE(CreatorSwCfgIdx);
    if (part_idx == OwnerSwCfgIdx)
        dai_addr inside `PART_CONTENT_RANGE(OwnerSwCfgIdx);
    if (part_idx == RotCreatorAuthCodesignIdx)
        dai_addr inside `PART_CONTENT_RANGE(RotCreatorAuthCodesignIdx);
    if (part_idx == RotCreatorAuthStateIdx)
        dai_addr inside `PART_CONTENT_RANGE(RotCreatorAuthStateIdx);
    if (part_idx == HwCfg0Idx)
        dai_addr inside `PART_CONTENT_RANGE(HwCfg0Idx);
    if (part_idx == HwCfg1Idx)
        dai_addr inside `PART_CONTENT_RANGE(HwCfg1Idx);
    if (part_idx == Secret0Idx)
        dai_addr inside `PART_CONTENT_RANGE(Secret0Idx);
    if (part_idx == Secret1Idx)
        dai_addr inside `PART_CONTENT_RANGE(Secret1Idx);
    if (part_idx == Secret2Idx)
        dai_addr inside `PART_CONTENT_RANGE(Secret2Idx);
    solve part_idx before dai_addr;
  }


  task body();
    bit [TL_DW-1:0] reg_rd_val, rdata0, rdata1, rdata0_pre, rdata1_pre;
    bit [TL_DW-1:0] addr;

    bit zeroized_partition [0:LifeCycleIdx-1];
    bit used_zeroized_addrs[bit [TL_DW-1:0]];

    bit dai_regwen_state = 1;

    for (int i = 0; i < NumPart; i++) begin
      // part_idx = otp_ctrl_part_pkg::part_idx_e'(i);
      part_idx = i;
      `uvm_info(`gfn, $sformatf("part_idx :%s, addr offset :%x",
                                 part_idx.name, PartInfo[i].offset), UVM_LOW);
    end

    super.body();

    this.rand_mode(0);
    this.dai_addr.rand_mode(1);
    this.part_idx.rand_mode(1);

    fork
      intr_service_routine();
      check_trigger_routine();
    join_none

    for (int i = 0; i < num_dai_op; i++) begin
      // Now randomize the partitions and address to zeroize
      `DV_CHECK_RANDOMIZE_FATAL(this)

      // First check if the partition zeroizable field is zeroized. If not set the field
      if (!part_is_zeroizable(part_idx)) begin
        `uvm_info(`gfn, $sformatf("ZRing Non Zeroizable Partition: part_idx :%s, dai_addr :%x",
                part_idx.name, dai_addr), UVM_LOW);
        dai_zeroize(.addr(dai_addr));
      end else begin
        if (!zeroized_partition[part_idx]) begin
          `uvm_info(`gfn, $sformatf("ZRing Partition: part_idx :%s, dai_addr :%x",
                  part_idx.name, zeroized_offset(part_idx)), UVM_LOW);
          dai_zeroize(.addr(zeroized_offset(part_idx)));
          zeroized_partition[part_idx] = 1;
        end

        if (used_zeroized_addrs.exists(dai_addr)) begin
          `uvm_info(`gfn, $sformatf("addr %0h is already written!", addr), UVM_MEDIUM)
          continue;
        end

        if (set_dai_regwen && dai_regwen_state) begin
          csr_rd(ral.direct_access_regwen, reg_rd_val);
          cfg.clk_rst_vif.wait_clks(5); // Delay needed before writing to the jsut read register
          `uvm_info(`gfn, $sformatf("Setting DAI Regwen to zero - Locking DAI"), UVM_LOW);
          dai_regwen_state = 0;
          csr_wr(ral.direct_access_regwen, dai_regwen_state);
        end

        // Before zeroizing a location read the current contents of the location so as to know if
        // zeroization was sucessful or not
        // dai_rd(dai_addr, rdata0_pre, rdata1_pre);

        // `uvm_info(`gfn, $sformatf("ZRing(Pre): part_idx :%s, dai_addr :%x, rdata0:%x, rdata1:%x",
        //           part_idx.name, dai_addr, rdata0_pre, rdata1_pre), UVM_LOW);
        dai_zeroize(.addr(dai_addr));
        used_zeroized_addrs[dai_addr] = 1;

        // Wait a cycle before issuing a read to direct_access_rdata registers to check if the
        // address is zeroized
        cfg.clk_rst_vif.wait_clks(1);

        // Once Zeroization command completes, if zerorization is sucessful rdata0 and rdata1 should
        // be return the current value of the zeroized otp location
        csr_rd(ral.direct_access_rdata[0], rdata0);
        if (is_granule_64(dai_addr))
          csr_rd(ral.direct_access_rdata[1], rdata1);

        `uvm_info(`gfn, $sformatf("ZRing(Post): part_idx :%s, dai_addr :%x, rdata0:%x, rdata1:%x",
                  part_idx.name, dai_addr, rdata0, rdata1), UVM_LOW);
      end
    end

    `uvm_info(`gfn, $sformatf("Starting Clock Delay - 1"), UVM_LOW);
    // Wait a few clocks before issuing a readback to check if the address is zeroized and holds
    // state post reset
    cfg.clk_rst_vif.wait_clks(10);
    `uvm_info(`gfn, $sformatf("Done Clock Delay - 1"), UVM_LOW);

    `uvm_info(`gfn, "Reseting OTP - Zeroization State should be saved", UVM_LOW);
    do_otp_ctrl_init = 0;
    dut_init();

    if (used_zeroized_addrs.num() != 0) begin
      `uvm_info(`gfn, $sformatf("used_zeroized_addrs[]: %d", used_zeroized_addrs.num()), UVM_LOW);
    end

    foreach (used_zeroized_addrs[addr]) begin
      `uvm_info(`gfn, $sformatf("Reading back ZRed Addr: %x", addr), UVM_LOW);
      dai_rd(addr, rdata0, rdata1);
    end

    `uvm_info(`gfn, $sformatf("Delay before sequence termination"), UVM_LOW);
    cfg.clk_rst_vif.wait_clks(25);
    `uvm_info(`gfn, $sformatf("Done Delay"), UVM_LOW);
  endtask : body

  // This is an interrupt service routine that waits for interrupt and clears the following
  // Registers
  // - INTR
  // - STATUS
  // - ERROR CODE
  task intr_service_routine();
    bit [DataWidth-1:0] intr_enable;
    bit [DataWidth-1:0] csr_rd_value;

    `uvm_info(`gfn, $sformatf("intr_service_routine - Starting"), UVM_LOW);


    wait (cfg.under_reset == 0);

    `uvm_info(`gfn, $sformatf("(ISR) Enabling OTP Error Interrupt"), UVM_LOW);
    intr_enable = intr_enable| 1 << 1;
    csr_wr(.ptr(ral.intr_enable), .value(intr_enable));

    forever begin
      @ (posedge cfg.under_reset or posedge cfg.intr_vif.pins[1]) begin
        if (cfg.under_reset) begin
          `uvm_info(`gfn, $sformatf("(ISR)- Reset Seen"), UVM_LOW);
          // Reset has been triggered, wait until OTP is initialized
          wait (cfg.under_reset == 0);
          wait (cfg.otp_ctrl_vif.pwr_otp_done_o == 1'b1);

          `uvm_info(`gfn, $sformatf("(ISR)- Re-Enabling Interrrupt after reset"), UVM_LOW);
          csr_wr(.ptr(ral.intr_enable), .value(intr_enable));
        end else if (cfg.intr_vif.pins[1] == 1'b1) begin
          cfg.clk_rst_vif.wait_clks($urandom_range(5, 10));
          `uvm_info(`gfn, $sformatf("(ISR)- OTP Error Interrupt Seen"), UVM_LOW);
          csr_rd(ral.intr_state, csr_rd_value);
          csr_wr(ral.intr_state, csr_rd_value);

          cfg.clk_rst_vif.wait_clks($urandom_range(5, 10));
          csr_rd(ral.status, csr_rd_value);
          csr_rd(ral.err_code[OtpDaiErrIdx], csr_rd_value);

          csr_wr(.ptr(ral.intr_enable), .value('{default:0}));
          csr_wr(.ptr(ral.intr_enable), .value(intr_enable));
        end
      end
    end
  endtask : intr_service_routine

  task check_trigger_routine();

    if (!enable_trigger_checks) begin
      `uvm_info(`gfn, $sformatf("check_trigger_routine - disabled"), UVM_LOW);
      return;
    end

    `uvm_info(`gfn, $sformatf("check_trigger_routine - Starting"), UVM_LOW);

    forever begin
      cfg.clk_rst_vif.wait_clks($urandom_range(10, 50));
      if (cfg.under_reset) begin
        `uvm_info(`gfn, $sformatf("(CTR) - Wait until Otp Init is done"), UVM_LOW);
        wait (cfg.under_reset == 0);
        wait (cfg.otp_ctrl_vif.pwr_otp_done_o == 1);
      end

      `uvm_info(`gfn, $sformatf("(CTR) - Starting Threads"), UVM_LOW);
      fork
        begin : Thread1
          `uvm_info(`gfn, $sformatf("(CTR)- Triggering Checks"), UVM_LOW);
          trigger_checks(.val(check_trigger_val), .wait_done(1), .wait_backdoor(1));
          `uvm_info(`gfn, $sformatf("(CTR)- Checks Completed"), UVM_LOW);
        end : Thread1
        begin : Thread2
            wait (cfg.under_reset);
            `uvm_info(`gfn, $sformatf("(CTR)- Reset Seen"), UVM_LOW);
        end : Thread2
      join_any
      disable fork;

      `uvm_info(`gfn, $sformatf("(CTR) - Threads Disabled"), UVM_LOW);
    end
  endtask : check_trigger_routine

endclass : otp_ctrl_zeroization_vseq

`undef PART_CONTENT_RANGE
