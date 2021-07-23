library(tidyverse)
library(scales)
d <- read_csv("./analysis/data/bad_net.csv")
baselines <- data.frame(
  proof_system = c("Groth16", "Marlin", "Plonk"),
  baseline = c(0.722, 2.209, 5.642)
)
dd <- d %>%
  mutate(proof_system = ifelse(proof_system == "groth16", "Groth16", proof_system)) %>%
  mutate(proof_system = ifelse(proof_system == "marlin", "Marlin", proof_system)) %>%
  mutate(proof_system = ifelse(proof_system == "plonk", "Plonk", proof_system)) %>%
  mutate() %>%
  left_join(baselines) %>%
  mutate(slowdown = time/baseline)

ggplot(dd, mapping = aes(x = kb_s / 2^10, y = slowdown, color = proof_system, shape=proof_system)) +
  geom_point(size=2) +
  geom_line() +
  scale_x_continuous(trans = log2_trans(),
                     breaks = trans_breaks("log2", function(x) 2^x),
                     labels = trans_format("log2", math_format(2^.x))) +
  scale_y_continuous(trans = log2_trans(),
                     breaks = trans_breaks("log2", function(x) 2^x),
                     labels = trans_format("log2", math_format(2^.x))) +
  # scale_x_continuous(trans = "log2",
  #                    breaks = x_breaks) +
  labs(
    y = "Slowdown",
    x = "Bandwidth (Mb/s)",
    color = "Proof System",
    shape = "Proof System",
  ) + 
  annotate("segment", x = 2^0, xend = 2^6, y =  1, yend= 1) +
  annotate("text", x = 2^3, y =1, vjust=-0.5, label ="high bandwidth")
ggsave("analysis/plots/bad_net.pdf", width = 4, height = 3, units = "in")