# Nazwa pliku wynikowego
TARGET = honeypot

# Kompilator i flagi
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -Iinclude -g

# Struktura katalogów
SRCDIR = src
INCDIR = include
OBJDIR = obj

# Pliki źródłowe i odpowiadające im pliki obiektowe
SRCS = $(wildcard $(SRCDIR)/*.c) main.c
OBJS = $(patsubst %.c, $(OBJDIR)/%.o, $(notdir $(SRCS)))

# Domyślna reguła
all: $(TARGET)

# Tworzenie pliku wykonywalnego
$(TARGET): $(OBJS) | $(OBJDIR)
	$(CC) $(CFLAGS) -o $@ $^

# Kompilacja poszczególnych plików do obj/
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/main.o: main.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Upewnij się, że katalog obj/ istnieje
$(OBJDIR):
	mkdir -p $(OBJDIR)

# Czyszczenie wyników kompilacji
clean:
	rm -rf $(OBJDIR) $(TARGET)

# Uruchomienie programu
run: $(TARGET)
	./$(TARGET)

-include $(DEPS)

.PHONY: all clean run
