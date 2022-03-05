library(tidyverse)
library(stringr)
library(scales)
d <- read_csv("./analysis/data/Npc.csv")
baseline_time = 0.346
dd <- d %>%
  filter(proof_system == "groth16") %>%
  mutate(proof_system = ifelse(proof_system == "groth16", "Groth16", proof_system)) %>%
  mutate(proof_system = ifelse(proof_system == "marlin", "Marlin", proof_system)) %>%
  mutate(proof_system = ifelse(proof_system == "plonk", "Plonk", proof_system)) %>%
  mutate(alg = ifelse(alg == "gsz", str_wrap("t < N/2",14), alg)) %>%
  mutate(alg = ifelse(alg == "spdz", str_wrap("t < N",14), alg)) %>%
  group_by(parties,alg,size,proof_system) %>% summarise(time=median(time)) %>% 
  mutate(slowdown = time/baseline_time) %>%
  mutate()

ggplot(dd, mapping = aes(x = parties, y = slowdown, color = alg, shape=alg)) +
  geom_point(size=2) +
  geom_line() +
  scale_x_continuous(trans = log2_trans(),
                     breaks = trans_breaks("log2", function(x) 2^x, 5),
                     minor_breaks = trans_breaks("log2", function(x) 2^x, 5),
                     labels = trans_format("log2", math_format(2^.x))) +
  scale_y_continuous(trans = log2_trans(),
                     breaks = trans_breaks("log2", function(x) 2^x, 4),
                     minor_breaks = trans_breaks("log2", function(x) 2^x, 4),
                     labels = trans_format("log2", math_format(2^.x))) +
  # scale_x_continuous(trans = "log2",
  #                    breaks = x_breaks) +
  labs(
    y = "Slowdown",
    x = "Parties",
    color = "ZK Threshold",
    shape = "ZK Threshold"
  ) +
  annotate("segment", x = 2^1, xend = 2^5, y =  1, yend= 1) +
  annotate("text", x = 2^4.0, y =1, vjust=-0.5, label ="single prover", size=2)
ggsave("analysis/plots/Npc.png", width = 3.00, height = 1.75, units = "in")
embedFonts("analysis/plots/Npc.pdf")
