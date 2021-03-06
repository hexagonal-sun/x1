#include <stdint.h>

typedef struct
{
    uint32_t MAC1;
    uint32_t MAC2;
    uint32_t IPGT;
    uint32_t IPGR;
    uint32_t CLRT;
    uint32_t MAXF;
    uint32_t SUPP;
    uint32_t TEST;
    uint32_t MCFG;
    uint32_t MCMD;
    uint32_t MADR;
    uint32_t MWTD;
    uint32_t MRDD;
    uint32_t MIND;
    uint32_t __reserved_0_[2];
    uint32_t SA0;
    uint32_t SA1;
    uint32_t SA2;
    uint32_t __reserved_1_[45];
    uint32_t Command;
    uint32_t Status;
    uint32_t RxDescriptor;
    uint32_t RxStatus;
    uint32_t RxDescriptorNumber;
    uint32_t RxProduceIndex;
    uint32_t RxConsumeIndex;
    uint32_t TxDescriptor;
    uint32_t TxStatus;
    uint32_t TxDescriptorNumber;
    uint32_t TxProduceIndex;
    uint32_t TxConsumeIndex;
    uint32_t __reserved_2_[10];
    uint32_t TSV0;
    uint32_t TSV1;
    uint32_t RSV;
    uint32_t __reserved_3_[3];
    uint32_t FlowControlCounter;
    uint32_t FlowControlStatus;
    uint32_t __reserved_4_[34];
    uint32_t RxFilterCtrl;
    uint32_t RxFilterWoLStatus;
    uint32_t RxFilterWoLClear;
    uint32_t __reserved_5_;
    uint32_t HashFilterL;
    uint32_t HashFilterH;
    uint32_t __reserved_6_[882];
    uint32_t IntStatus;
    uint32_t IntEnable;
    uint32_t IntClear;
    uint32_t IntSet;
    uint32_t __reserved_7_;
    uint32_t PowerDown;
    uint32_t __reserved_8_;
    uint32_t Module_ID;
} lpc_periph_emac_t;

typedef struct
{
    uint32_t IR;
    uint32_t TCR;
    uint32_t TC;
    uint32_t PR;
    uint32_t PC;
    uint32_t MCR;
    uint32_t MR0;
    uint32_t MR1;
    uint32_t MR2;
    uint32_t MR3;
    uint32_t CCR;
    uint32_t CR0;
    uint32_t CR1;
    uint32_t __reserved_0_[2];
    uint32_t EMR;
    uint32_t __reserved_1_[12];
    uint32_t CTCR;
} lpc_periph_timer_t;

typedef struct
{
    uint32_t FLASHCFG;
    uint32_t __reserved_0_[31];
    uint32_t PLL0CON;
    uint32_t PLL0CFG;
    uint32_t PLL0STAT;
    uint32_t PLL0FEED;
    uint32_t __reserved_1_[4];
    uint32_t PLL1CON;
    uint32_t PLL1CFG;
    uint32_t PLL1STAT;
    uint32_t PLL1FEED;
    uint32_t __reserved_2_[4];
    uint32_t PCON;
    uint32_t PCONP;
    uint32_t __reserved_3_[15];
    uint32_t CCLKCFG;
    uint32_t USBCLKCFG;
    uint32_t CLKSRCSEL;
    uint32_t CANSLEEPCLR;
    uint32_t CANWAKEFLAGS;
    uint32_t __reserved_4_[10];
    uint32_t EXTINT;
    uint32_t __reserved_5_;
    uint32_t EXTMODE;
    uint32_t EXTPOLAR;
    uint32_t __reserved_6_[12];
    uint32_t RSID;
    uint32_t __reserved_7_[7];
    uint32_t SCS;
    uint32_t IRCTRIM;
    uint32_t PCLKSEL0;
    uint32_t PCLKSEL1;
    uint32_t __reserved_8_[4];
    uint32_t USBIntSt;
    uint32_t DMAREQSEL;
    uint32_t CLKOUTCFG;
} lpc_periph_sc_t;

typedef struct
{
    uint32_t PINSEL0;
    uint32_t PINSEL1;
    uint32_t PINSEL2;
    uint32_t PINSEL3;
    uint32_t PINSEL4;
    uint32_t PINSEL5;
    uint32_t PINSEL6;
    uint32_t PINSEL7;
    uint32_t PINSEL8;
    uint32_t PINSEL9;
    uint32_t PINSEL10;
    uint32_t __reserved_0_[5];
    uint32_t PINMODE0;
    uint32_t PINMODE1;
    uint32_t PINMODE2;
    uint32_t PINMODE3;
    uint32_t PINMODE4;
    uint32_t PINMODE5;
    uint32_t PINMODE6;
    uint32_t PINMODE7;
    uint32_t PINMODE8;
    uint32_t PINMODE9;
    uint32_t PINMODE_OD0;
    uint32_t PINMODE_OD1;
    uint32_t PINMODE_OD2;
    uint32_t PINMODE_OD3;
    uint32_t PINMODE_OD4;
    uint32_t I2CPADCFG;
} lpc_periph_pincon_t;


typedef struct
{
    uint32_t ISER0;
    uint32_t ISER1;
    uint32_t ISER2;
    uint32_t ISER3;
    uint32_t __reserved_0_[28];
    uint32_t ICER0;
    uint32_t ICER1;
    uint32_t ICER2;
    uint32_t ICER3;
    uint32_t __reserved_1_[28];
    uint32_t ISPR0;
    uint32_t ISPR1;
    uint32_t ISPR2;
    uint32_t ISPR3;
    uint32_t __reserved_2_[28];
    uint32_t ICPR0;
    uint32_t ICPR1;
    uint32_t ICPR2;
    uint32_t ICPR3;
    uint32_t __reserved_3_[28];
    uint32_t IABR0;
    uint32_t IABR1;
    uint32_t IABR2;
    uint32_t IABR3;
    uint32_t __reserved_4_[60];
    uint32_t IPR0;
    uint32_t IPR1;
    uint32_t IPR2;
    uint32_t IPR3;
    uint32_t IPR4;
    uint32_t IPR5;
    uint32_t IPR6;
    uint32_t IPR7;
    uint32_t IPR8;
    uint32_t IPR9;
    uint32_t IPR10;
    uint32_t IPR11;
    uint32_t IPR12;
    uint32_t IPR13;
    uint32_t IPR14;
    uint32_t IPR15;
    uint32_t IPR16;
    uint32_t IPR17;
    uint32_t IPR18;
    uint32_t IPR19;
    uint32_t IPR20;
    uint32_t IPR21;
    uint32_t IPR22;
    uint32_t IPR23;
    uint32_t IPR24;
    uint32_t IPR25;
    uint32_t IPR26;
    uint32_t IPR27;
    uint32_t __reserved_5_[676];
    uint32_t STIR;
} lpc_core_nvic_t;

typedef struct
{
    uint32_t CPUID;
    uint32_t ICSR;
    uint32_t VTOR;
    uint32_t AIRCR;
    uint32_t SCR;
    uint32_t CCR;
    uint8_t  SHP[12];
    uint32_t SHCSR;
    uint32_t CFSR;
    uint32_t HFSR;
    uint32_t DFSR;
    uint32_t MMFAR;
    uint32_t BFAR;
    uint32_t AFSR;
    uint32_t PFR[2];
    uint32_t DFR;
    uint32_t ADR;
    uint32_t MMFR[4];
    uint32_t ISAR[5];
} lpc_core_scb_t;

typedef struct
{
    uint32_t tx_rx_dll;
    uint32_t ier_dlm;
    uint32_t iir_fcr;
    uint32_t lcr;
    uint32_t __reserved_1;
    uint32_t lsr;
    uint32_t __reserved_2;
    uint32_t scr;
    uint32_t acr;
    uint32_t icr;
    uint32_t fdr;
    uint32_t __reserved_3;
    uint32_t ter;
}lpc_periph_uart_t;

#define UART_DLAB_SHIFT 7
#define UART_DIVADDVAL_SHIFT 0
#define UART_MULVAL_SHIFT 4
#define UART_FIFO_EN_SHIFT 0
#define UART_THRE_MASK (1 << 5)
#define UART_RDR_MASK 1

#define ICSR_PENDSVSET_MASK (1 << 28)
#define SCR_SLEEPONEXIT_MASK (1 << 1)

static volatile lpc_periph_emac_t   * const LPC_EMAC   = (lpc_periph_emac_t *)0x50000000;
static volatile lpc_periph_sc_t     * const LPC_SC     = (lpc_periph_sc_t *)0x400FC000;
static volatile lpc_periph_pincon_t * const LPC_PINCON = (lpc_periph_pincon_t *)0x4002C000;
static volatile lpc_periph_timer_t  * const LPC_TIM0   = (lpc_periph_timer_t *)0x40004000;
static volatile lpc_periph_timer_t  * const LPC_TIM1   = (lpc_periph_timer_t *)0x40008000;
static volatile lpc_periph_timer_t  * const LPC_TIM2   = (lpc_periph_timer_t *)0x40090000;
static volatile lpc_periph_timer_t  * const LPC_TIM3   = (lpc_periph_timer_t *)0x40094000;
static volatile lpc_core_nvic_t     * const LPC_NVIC   = (lpc_core_nvic_t *)0xE000E100;
static volatile lpc_core_scb_t      * const LPC_SCB    = (lpc_core_scb_t  *)0xE000ED00;
static volatile lpc_periph_uart_t   * const LPC_UART0  = (lpc_periph_uart_t *)0x4000C000;
