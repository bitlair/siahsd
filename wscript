#! /usr/bin/env python
# encoding: utf-8
from waflib.Task import Task
from waflib.TaskGen import extension

class idl_header(Task):
    run_str = '../bin/pidl/pidl --header ${TGT[0].abspath()} ${SRC}'
    color   = 'BLUE'
    ext_out = ['.h']

class idl_parser(Task):
    run_str = '../bin/pidl/pidl --ndr-parser ${TGT[0].abspath()} ${SRC}'
    color   = 'BLUE'
    ext_out = ['.h']

@extension('.idl')
def process_idl(self, node):
    header_node = node.change_ext('.h')
    self.create_task('idl_header', node, [header_node ]) 

    c_node = node.change_ext('.c')

    if c_node.name[:len('ndr_')] != 'ndr_':
        c_node.name = 'ndr_' + c_node.name

    self.create_task('idl_parser', node, [ c_node ]) 
    self.source.append(c_node)

def dist(ctx):
        ctx.base_name = 'siahsd'
        ctx.algo      = 'tar.bz2'
        ctx.excl      = ' **/.waf-1* **/*~ **/*.o **/*.swp **/.lock-w*'
        ctx.files     = ctx.path.ant_glob('**/wscript')

def configure(conf):
    conf.env.CC = 'gcc'
    conf.load('gcc')

    # Check for glib
    conf.check_cfg(package='glib-2.0', uselib_store='glib-2.0',
                args=['--cflags', '--libs'])
    
    # Check for talloc
    conf.check_cfg(package='talloc', uselib_store='talloc',
                args=['--cflags', '--libs' ])

    # Check for samba-4.0
    conf.check_cfg(package='samba-util', uselib_store='samba',
                args=['--cflags', '--libs' ])

    # Check for ndr
    conf.check_cfg(package='ndr', uselib_store='samba',
                args=['--cflags', '--libs'])


    # Check for headers
    conf.check(header_name='stdio.h', features='c cprogram')
    conf.check(header_name='stdlib.h', features='c cprogram')
    conf.check(header_name='stdint.h', features='c cprogram')
    conf.check(header_name='stdbool.h', features='c cprogram')
    conf.check(header_name='sys/time.h', features='c cprogram')
    conf.check(header_name='sys/types.h', features='c cprogram')
    conf.check(header_name='sys/stat.h', features='c cprogram')
    conf.check(header_name='netinet/in.h', features='c cprogram')
    conf.check(header_name='arpa/inet.h', features='c cprogram')
    conf.check(header_name='unistd.h', features='c cprogram')
    conf.check(header_name='string.h', features='c cprogram')
    conf.check(header_name='fcntl.h', features='c cprogram')
    conf.check(header_name='errno.h', features='c cprogram')


    # Used libraries
    conf.check(header_name='talloc.h', use='samba', features='c cprogram')
    conf.check(header_name='glib.h', use='glib-2.0', features='c cprogram')
    conf.check(header_name='glibconfig.h', use='glib-2.0', features='c cprogram')

    conf.check(header_name='dbi/dbi.h', features='c cprogram')
    conf.check(header_name='util/data_blob.h', use='samba', features='c cprogram')
    conf.check(header_name='core/ntstatus.h', use='samba', features='c cprogram')
    conf.check(header_name='charset.h', use='samba', features='c cprogram')

    conf.check_cc(lib='dbi', uselib_store='dbi')
    conf.check_cc(lib='talloc', uselib_store='samba')
    conf.check_cc(lib='ndr', uselib_store='ndr')
    conf.check_cc(lib='gmp', uselib_store='nettle')
    conf.check_cc(lib='hogweed', uselib_store='nettle')
    conf.check_cc(lib='nettle', uselib_store='nettle')

    # Purposefully at the bottom because waf configuration tests fail with -Wstrict-prototypes and -Werror
    conf.env.CFLAGS = ['-O0', '-g', '-ggdb', '-std=c99', '-Wall', '-Wshadow', '-Wpointer-arith', '-Wcast-align', '-Wwrite-strings', '-Wdeclaration-after-statement', 
                      '-Werror-implicit-function-declaration', '-Wstrict-prototypes', '-Werror']

def build(bld):
    bld.stlib(source="database.c", target="database", use='glib-2.0')
    bld.stlib(source="status.c", target="status", use='glib-2.0')
    bld.stlib(source="config.c", target="config", use='glib-2.0 database jsonbot')
    bld.stlib(source="sia.c", target="sia", use='glib-2.0')
    bld.stlib(source="siahs.c", target="siahs", use='glib-2.0')
    bld.stlib(source="jsonbot.c", target="jsonbot", use='glib-2.0')

    bld.program(
                source = 'siahsd.c',
                target = 'siahsd',
                use    = [ 'database', 'config', 'status', 'sia', 'siahs', 'jsonbot', 'dbi', 'talloc', 'glib-2.0', 'nettle' ])

    bld.program(
                source = 'secip.idl secipd.c crc16.c',
                target = 'secipd',
                use    = [ 'database', 'config', 'status', 'sia', 'siahs', 'jsonbot', 'dbi', 'samba', 'glib-2.0', 'nettle', 'ndr' ])
    pass

def clean(ctx):
    pass
