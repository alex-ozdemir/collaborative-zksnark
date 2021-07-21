library(tidyverse)
library(scales)
d <- read_csv("./analysis/data/weak.csv")
dd <- d
dd$alg <- paste(dd$alg, dd$parties, sep="")
dd <- dd %>%
  mutate(alg = ifelse(alg == "local1", "Single Prover", alg)) %>%
  mutate(alg = ifelse(alg == "spdz2", "SPDZ 2", alg)) %>%
  mutate(alg = ifelse(alg == "spdz3", "SPDZ 3", alg)) %>%
  mutate(alg = ifelse(alg == "gsz3", "GSZ/DN 3", alg))%>%
  mutate(proof_system = ifelse(proof_system == "groth16", "Groth16", proof_system)) %>%
  mutate(proof_system = ifelse(proof_system == "marlin", "Marlin", proof_system)) %>%
  mutate(proof_system = ifelse(proof_system == "plonk", "Plonk", proof_system)) %>%
  mutate()

x_breaks = c(0:20 %>% map(function (x) 2 ^x)) %>% as_vector()
x_labels = c(math_format(2^.x)(0:20))
c(1,2)

ggplot(dd, mapping = aes(x = size, y = time, color = alg)) +
  geom_point() +
  geom_line() +
  facet_wrap(vars(proof_system)) +
  scale_x_continuous(trans = log2_trans(),
                     limits = c(1, 2^20),
                     breaks = trans_breaks("log2", function(x) 2^x),
                     labels = trans_format("log2", math_format(2^.x))) +
  scale_y_continuous(trans = log2_trans(),
                     breaks = trans_breaks("log2", function(x) 2^x),
                     labels = trans_format("log2", math_format(2^.x))) +
  # scale_x_continuous(trans = "log2",
  #                    breaks = x_breaks) +
  labs(
    y = "Time (s)",
    x = "Constraints",
    color = "MPC Type"
  )
ggsave("analysis/plots/mpc.pdf", width = 8, height = 3, units = "in")
             