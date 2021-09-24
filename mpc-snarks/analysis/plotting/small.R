library(tidyverse)
library(latex2exp)
library(stringr)
library(scales)
d <- bind_rows(read_csv("./analysis/data/weak.csv"), read_csv("./analysis/data/6pc.csv"))
dd <- d
dd$alg <- paste(dd$alg, dd$parties, sep="")
dd <- dd %>%
  filter(parties < 4) %>%
  filter(proof_system == "groth16") %>%
  mutate(alg = ifelse(alg == "local1", str_wrap("one prover (baseline)", 14), alg)) %>%
  mutate(alg = ifelse(alg == "spdz2",  str_wrap("1 of 2 corrupt", 14), alg)) %>%
  mutate(alg = ifelse(alg == "spdz3",  str_wrap("2 of 3 corrupt", 14), alg)) %>%
  mutate(alg = ifelse(alg == "gsz3",   str_wrap("1 of 3 corrupt", 14), alg))%>%
  mutate(proof_system = ifelse(proof_system == "groth16", "Groth16", proof_system)) %>%
  mutate(proof_system = ifelse(proof_system == "marlin", "Marlin", proof_system)) %>%
  mutate(proof_system = ifelse(proof_system == "plonk", "Plonk", proof_system)) %>%
  mutate() %>%
  group_by(alg, proof_system, size) %>%
  summarise(time=median(time))

x_breaks = c(0:20 %>% map(function (x) 2 ^x)) %>% as_vector()
x_labels = c(math_format(2^.x)(0:20))
c(1,2)

ggplot(dd, mapping = aes(x = size, y = time, color = alg, shape = alg)) +
  geom_point() +
  geom_line() +
  scale_x_continuous(trans = log2_trans(),
                     limits = c(2^5, 2^15),
                     breaks = trans_breaks("log2", function(x) 2^x, 3),
                     labels = trans_format("log2", math_format(2^.x))) +
  scale_y_continuous(trans = log2_trans(),
                     limits = c(2^-5, 2^5),
                     breaks = trans_breaks("log2", function(x) 2^x, 3),
                     labels = trans_format("log2", math_format(2^.x)),
                     minor_breaks = trans_breaks("log2", function(x) 2^x, 11),
                     ) +
  scale_shape_manual(values = c(1, 2, 3, 4, 5, 6)) +
  # scale_x_continuous(trans = "log2",
  #                    breaks = x_breaks) +
  labs(
    y = "Time (s)",
    x = TeX("Size of $\\phi$ (R1CS constraints)"),
    color = "Provers",
    shape = "Provers"
  ) +
  theme(legend.key.height = unit(1.75, 'lines'))
ggsave("analysis/plots/small.pdf", width = 3.5, height = 2.5, units = "in")
