#include <sys/stat.h>
#include <sys/types.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <link.h>
#include <libelf.h>
#include <gelf.h>
#include <unistd.h>
#include <sys/mman.h>

#include <cassert>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <iterator>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include <exception>
#include <memory>
#include <boost/format.hpp>

struct module
{
  std::shared_ptr <Elf> elf;
  std::vector <void *> mappings;
  std::map <std::string, GElf_Addr> symbols;

  module () {}

  module (std::shared_ptr <Elf> a_elf)
    : elf (a_elf)
  {}
};

std::map <std::string, module> modules;

void
help ()
{
}

void
load (std::string const &arg)
{
  std::cout << "load '" << arg << '\'' << std::endl;
  int fd = open (arg.c_str (), O_RDONLY);
  if (fd < 0)
    {
    sys_err:
      throw std::runtime_error (str (boost::format ("%s: %s")
				     % arg % strerror (errno)));
    }

  // We map RDWR.  We will use this mapping to update the image.
  // elf_rawdata will tell us the address of the image that libelf
  // mapped in.
  std::shared_ptr <Elf> elf (elf_begin (fd, ELF_C_RDWR_MMAP, nullptr),
			     [fd] (Elf *elf)
			     {
			       std::cout << "cleanup" << std::endl;
			       close (fd);
			       elf_end (elf);
			     });
  if (elf == nullptr)
    {
    elf_err:
      throw std::runtime_error (str (boost::format ("%s: %s")
				     % arg % elf_errmsg (elf_errno ())));
    }

  GElf_Ehdr ehdr;
  if (gelf_getehdr (&*elf, &ehdr) == nullptr)
    goto elf_err;

#ifndef __x86_64__
# error Only x86_64 supported at this time.
#endif
  assert (ehdr.e_machine == EM_X86_64
	  && ehdr.e_ident[EI_CLASS] == ELFCLASS64);

  if (ehdr.e_type != ET_DYN)
    throw std::runtime_error
      (str (boost::format ("%s: Only DSO modules supported as of now.") % arg));

  ssize_t pgsz = sysconf (_SC_PAGESIZE);
  if (pgsz == -1)
    goto sys_err;

  module m (elf);

  void *base = nullptr;
  for (int i = 0; i < ehdr.e_phnum; ++i)
    {
      GElf_Phdr phdr;
      if (gelf_getphdr (&*elf, i, &phdr) == nullptr)
	goto elf_err;

      switch (phdr.p_type)
	{
	case PT_DYNAMIC:
	  {
	    Elf_Data *data = elf_getdata_rawchunk (&*elf, phdr.p_offset,
						   phdr.p_filesz, ELF_T_DYN);
	    if (data == nullptr)
	      goto elf_err;

	    GElf_Addr symtab_addr = 0, strtab_addr = 0;
	    GElf_Off syment = 0, strsz = 0;

	    GElf_Dyn dyn;
	    for (int i = 0; ; ++i)
	      if (gelf_getdyn (data, i, &dyn) == nullptr)
		break;
	      else
		switch (dyn.d_tag)
		  {
		  case DT_SYMTAB:
		    symtab_addr = dyn.d_un.d_val;
		    break;
		  case DT_SYMENT:
		    syment = dyn.d_un.d_val;
		    break;
		  case DT_STRTAB:
		    strtab_addr = dyn.d_un.d_val;
		    break;
		  case DT_STRSZ:
		    strsz = dyn.d_un.d_val;
		    break;
		  }

	    if (symtab_addr == 0 || syment == 0
		|| strtab_addr == 0 || strsz == 0)
	      throw std::runtime_error
		(str (boost::format ("%s: DYNAMIC section lacks one of, "
				     "DT_SYMTAB, DT_SYMENT, DT_STRTAB, "
				     "DT_STRSZ.") % arg));

	    Elf_Data *strtab = elf_getdata_rawchunk (&*elf, strtab_addr,
						     strsz, ELF_T_BYTE);
	    if (strtab == nullptr)
	      goto elf_err;

	    /* From glibc: """We assume that the string table follows
    	       the symbol table, because there is no way in ELF to
    	       know the size of the dynamic symbol table without
    	       looking at the section headers."""  */
	    assert (strtab_addr > symtab_addr);
	    GElf_Off symtab_sz = strtab_addr - symtab_addr;
	    Elf_Data *symtab = elf_getdata_rawchunk (&*elf, symtab_addr,
						     symtab_sz, ELF_T_SYM);
	    if (symtab == nullptr)
	      goto elf_err;

	    GElf_Sym sym;
	    for (int i = 0; ; ++i)
	      if (gelf_getsym (symtab, i, &sym) == nullptr
		  || sym.st_name >= strtab->d_size)
		break;
	      else if (((char *) strtab->d_buf)[sym.st_name] != 0
		       && GELF_ST_TYPE (sym.st_info) == STT_FUNC
		       && sym.st_value != 0)
		m.symbols[((char *) strtab->d_buf + sym.st_name)]
		  = sym.st_value;
	  }
	  break;

	case PT_LOAD:
	  {
	    // Taken from glibc.
	    GElf_Addr mapstart = phdr.p_vaddr & ~(pgsz - 1);
	    GElf_Addr mapend = ((phdr.p_vaddr + phdr.p_filesz + pgsz - 1)
				& ~(pgsz - 1));
	    GElf_Addr dataend = phdr.p_vaddr + phdr.p_filesz;
	    GElf_Addr allocend = phdr.p_vaddr + phdr.p_memsz;
	    GElf_Off mapoff = phdr.p_offset & ~(pgsz - 1);

	    int prot = 0;
	    if (phdr.p_flags & PF_R)
	      prot |= PROT_READ;
	    if (phdr.p_flags & PF_W)
	      prot |= PROT_WRITE;
	    if (phdr.p_flags & PF_X)
	      prot |= PROT_EXEC;

	    void *fix = base != nullptr ? (char *) base + mapstart : nullptr;
	    std::cout << "  LOAD start=" << std::hex << mapstart << "; end=" << mapend
		      << "; fix=" << fix << "; prot=" << std::oct << prot << std::hex
		      << "; dataend=" << dataend << "; allocend=" << allocend
		      << "; off=" << mapoff << std::dec
		      << std::endl;

	    void *addr = mmap (fix, allocend - mapstart, prot,
			       MAP_PRIVATE | MAP_FILE
			       | (fix != nullptr ? MAP_FIXED : 0),
			       fd, mapoff);
	    if (addr == MAP_FAILED)
	      goto sys_err;

	    m.mappings.push_back (addr);

	    if (base == nullptr)
	      {
		base = addr;
		std::cout << "  BASE is " << std::hex << base << std::dec << std::endl;
	      }
	    else
	      assert (addr == fix);
	  }
	  break;
	}
    }

  for (auto &sym: m.symbols)
    sym.second += (GElf_Addr) (uintptr_t) base;

  modules[arg] = m;
  std::cout << "  OK" << std::endl;
}

int
jmp (std::istringstream &ss)
{
  std::string word;
  ss >> word;

  for (auto const &module: modules)
    {
      auto it = module.second.symbols.find (word);
      if (it != module.second.symbols.end ())
	{
	  std::vector <char *> args;
	  do
	    {
	      char *buf = new char[word.length () + 1];
	      std::copy (std::begin (word), std::end (word), buf);
	      buf[word.length ()] = 0;
	      args.push_back (buf);
	    }
	  while (ss >> word);
	  args.push_back (nullptr);

	  GElf_Addr addr = it->second;
	  int ret = ((int (*) (int, char*[])) (uintptr_t) addr)
	    (args.size () - 1, &args[0]);

	  for (char *buf: args)
	    delete[] buf;

	  return ret;
	}
    }

  std::cerr << "No such symbol: " << word << std::endl;
  return -1;
}

std::string
arg (std::istringstream &ss)
{
  while (isspace (ss.peek ()))
    ss.ignore ();

  std::string arg;
  std::getline (ss, arg);
  return arg;
}

int
main (int argc, char *argv[])
{
  elf_version (EV_CURRENT);
  std::string line;

  while (std::getline (std::cin, line))
    {
      std::istringstream ss {line};
      std::string comm;
      ss >> comm;

      if (comm == "help" || comm == "h" || comm == "?")
	help ();
      else if (comm == "load" || comm == "l")
	load (arg (ss));
      else if (comm == "jmp" || comm == "j")
	{
	  int ret = jmp (ss);
	  std::cout << "return code: " << ret << std::endl;
	}
    }

  return 0;
}
