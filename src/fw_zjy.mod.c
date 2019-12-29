#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xa683b406, "module_layout" },
	{ 0x4debdc3, "sock_release" },
	{ 0xc996d097, "del_timer" },
	{ 0x5d3b55b5, "nf_unregister_hook" },
	{ 0x7edbf8c2, "netlink_kernel_create" },
	{ 0x95f3164e, "init_net" },
	{ 0xbe2c0274, "add_timer" },
	{ 0xfb0e29f, "init_timer_key" },
	{ 0xadc2290a, "nf_register_hook" },
	{ 0xd3fa43d6, "kfree_skb" },
	{ 0xb742fd7, "simple_strtol" },
	{ 0xe914e41e, "strcpy" },
	{ 0x2bc95bd4, "memset" },
	{ 0xd3f09f05, "netlink_unicast" },
	{ 0x279bd6d2, "__nlmsg_put" },
	{ 0xb76ca35f, "__alloc_skb" },
	{ 0x2e60bace, "memcpy" },
	{ 0xd0d8621b, "strlen" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x61651be, "strcat" },
	{ 0x91715312, "sprintf" },
	{ 0x50eedeb8, "printk" },
	{ 0x8834396c, "mod_timer" },
	{ 0x7d11c268, "jiffies" },
	{ 0xb4390f9a, "mcount" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "9B621BA52B1309A53ED88E7");
