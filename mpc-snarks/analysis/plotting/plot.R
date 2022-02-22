library(tidyverse)
library(stringr)
library(scales)
d <- bind_rows(read_csv("./analysis/data/weak_1_20.csv"), read_csv("./analysis/data/6pc.csv"))
dd <- d
dd$alg <- paste(dd$alg, dd$parties, sep="")
dd <- dd %>%
  filter(parties < 4) %>%
  mutate(alg = ifelse(alg == "local1", str_wrap("Single Prover", 14), alg)) %>%
  mutate(alg = ifelse(alg == "spdz2",  str_wrap("2PC: Dishonest Maj. (SDPZ)", 14), alg)) %>%
  mutate(alg = ifelse(alg == "spdz3",  str_wrap("3PC: Dishonest Maj. (SDPZ)", 14), alg)) %>%
  mutate(alg = ifelse(alg == "gsz3",   str_wrap("3PC: Honest Maj. (GSZ)", 14), alg))%>%
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
  facet_wrap(vars(proof_system)) +
  scale_x_continuous(trans = log2_trans(),
                     limits = c(2^0, 2^20),
                     breaks = trans_breaks("log2", function(x) 2^x),
                     labels = trans_format("log2", math_format(2^.x))) +
  scale_y_continuous(trans = log2_trans(),
                     breaks = trans_breaks("log2", function(x) 2^x, 5),
                     labels = trans_format("log2", math_format(2^.x)),
                     minor_breaks = trans_breaks("log2", function(x) 2^x, 21),
                     ) +
  scale_shape_manual(values = c(1, 2, 3, 4, 5, 6)) +
  # scale_x_continuous(trans = "log2",
  #                    breaks = x_breaks) +
  labs(
    y = "Time (s)",
    x = "Constraints",
    color = "MPC Type",
    shape = "MPC Type"
  ) +
  theme(legend.key.height = unit(1.75, 'lines'))
ggsave("analysis/plots/mpc.pdf", width = 6, height = 2.5, units = "in")
embedFonts("analysis/plots/mpc.pdf")
