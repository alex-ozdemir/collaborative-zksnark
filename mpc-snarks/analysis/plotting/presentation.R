library(tidyverse)
library(scales)
trials <- read_csv("./analysis/data/weak_1_20.csv")
ord <- c("Single Prover        ", "2 Provers (1-ZK)", "3 Provers (2-ZK)", "3 Provers (1-ZK)")
pts <- trials %>% 
  filter(proof_system == "groth16" & (net == "lan" | alg == "local") & parties <= 3) %>%
  filter(size <= 2 ** 15) %>%
  group_by(alg, parties, size) %>%
  summarise(mean_time = mean(time), .groups = "drop") %>%
  mutate(cfg = ifelse(alg == "local", "Single Prover        ", alg)) %>%
  mutate(cfg = ifelse(alg == "spdz" & parties == 2,  "2 Provers (1-ZK)", cfg)) %>%
  mutate(cfg = ifelse(alg == "spdz" & parties == 3,  "3 Provers (2-ZK)", cfg)) %>%
  mutate(cfg = ifelse(alg == "gsz" & parties == 3,   "3 Provers (1-ZK)", cfg)) %>%
  mutate(cfg = factor(cfg, levels = ord)) %>%
  mutate()


myplot <- function(data, name) {
  ggplot(data, aes(x = size, y = mean_time, color = cfg, shape = cfg, linetype = cfg)) +
    geom_line() + 
    geom_point(size=3) + 
    scale_x_continuous(trans = log2_trans(),
                       limits = c(2^0, 2^15),
                       breaks = trans_breaks("log2", function(x) 2^x),
                       labels = trans_format("log2", math_format(2^.x)),
                       minor_breaks = trans_breaks("log2", function(x) 2^x, 16)) +
    scale_y_continuous(trans = log2_trans(),
                       breaks = trans_breaks("log2", function(x) 2^x, 6),
                       labels = trans_format("log2", math_format(2^.x)),
                       limits = c(2^-8, 2^4),
                       minor_breaks = trans_breaks("log2", function(x) 2^x, 13),
    ) + 
    theme_minimal() + labs(
      x = "Statement Complexity (R1CS constraints)",
      y = "Proving Time (s)",
      shape = "System",
      color = "System",
      linetype = "System"
    )
  height_in = 3
  ggsave(name, height=height_in, width=height_in*16/9, units = "in") 
}

myplot(pts %>% filter(cfg == "Single Prover        "), "1.pdf")
myplot(pts %>% filter(cfg == "Single Prover        " | cfg == "2 Provers (1-ZK)"), "2.pdf")
myplot(pts %>% filter(alg != "gsz"), "3.pdf")
myplot(pts, "4.pdf")
  
  