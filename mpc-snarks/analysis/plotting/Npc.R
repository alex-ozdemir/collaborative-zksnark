library(tidyverse)
library(scales)
d <- read_csv("./analysis/data/Npc.csv")
baselines <- data.frame(
  alg = c("Malicious Maj.", "Honest Maj."),
  baseline = c(0.726, 0.448)
)
dd <- d %>%
  filter(proof_system == "groth16") %>%
  mutate(proof_system = ifelse(proof_system == "groth16", "Groth16", proof_system)) %>%
  mutate(proof_system = ifelse(proof_system == "marlin", "Marlin", proof_system)) %>%
  mutate(proof_system = ifelse(proof_system == "plonk", "Plonk", proof_system)) %>%
  mutate(alg = ifelse(alg == "gsz", "Honest Maj.", alg)) %>%
  mutate(alg = ifelse(alg == "spdz", "Malicious Maj.", alg)) %>%
  group_by(parties,alg,size,proof_system) %>% summarise(time=mean(time)) %>%
  left_join(baselines) %>%
  mutate(slowdown = time/baseline) %>%
  mutate()

ggplot(dd, mapping = aes(x = parties, y = slowdown, color = alg, shape=alg)) +
  geom_point(size=2) +
  geom_line() +
  scale_x_continuous(trans = log2_trans(),
                     breaks = trans_breaks("log2", function(x) 2^x, 5),
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
    color = "MPC Type",
    shape = "MPC Type"
  ) +
  annotate("segment", x = 2^1, xend = 2^5, y =  1, yend= 1) +
  annotate("text", x = 2^4.3, y =1, vjust=-0.5, label ="3 parties", size=2)
ggsave("analysis/plots/Npc.pdf", width = 3.00, height = 2.00, units = "in")
