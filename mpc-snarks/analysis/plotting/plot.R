library(tidyverse)
library(scales)
d <- bind_rows(read_csv("./analysis/data/weak.csv"), read_csv("./analysis/data/6pc.csv"))
dd <- d
dd$alg <- paste(dd$alg, dd$parties, sep="")
dd <- dd %>%
  mutate(alg = ifelse(alg == "local1", "Single Prover", alg)) %>%
  mutate(alg = ifelse(alg == "spdz2", "2PC: Malicious Maj.", alg)) %>%
  mutate(alg = ifelse(alg == "spdz3", "3PC: Malicious Maj.", alg)) %>%
  mutate(alg = ifelse(alg == "gsz3", "3PC: Honest Maj.", alg))%>%
  mutate(alg = ifelse(alg == "spdz6", "6PC: Malicious Maj.", alg)) %>%
  mutate(alg = ifelse(alg == "gsz6", "6PC: Honest Maj.", alg))%>%
  mutate(proof_system = ifelse(proof_system == "groth16", "Groth16", proof_system)) %>%
  mutate(proof_system = ifelse(proof_system == "marlin", "Marlin", proof_system)) %>%
  mutate(proof_system = ifelse(proof_system == "plonk", "Plonk", proof_system)) %>%
  filter(parties < 4) %>%
  mutate() %>%
  group_by(alg, proof_system, size) %>%
  summarise(time=mean(time))

x_breaks = c(0:20 %>% map(function (x) 2 ^x)) %>% as_vector()
x_labels = c(math_format(2^.x)(0:20))
c(1,2)

ggplot(dd, mapping = aes(x = size, y = time, color = alg, shape = alg)) +
  geom_point() +
  geom_line() +
  facet_wrap(vars(proof_system)) +
  scale_x_continuous(trans = log2_trans(),
                     limits = c(2^0, 2^15),
                     breaks = trans_breaks("log2", function(x) 2^x),
                     labels = trans_format("log2", math_format(2^.x))) +
  scale_y_continuous(trans = log2_trans(),
                     breaks = trans_breaks("log2", function(x) 2^x, 4),
                     labels = trans_format("log2", math_format(2^.x)),
                     minor_breaks = trans_breaks("log2", function(x) 2^x, 16),
                     ) +
  scale_shape_manual(values = c(1, 2, 3, 4, 5, 6)) +
  # scale_x_continuous(trans = "log2",
  #                    breaks = x_breaks) +
  labs(
    y = "Time (s)",
    x = "Constraints",
    color = "MPC Type",
    shape = "MPC Type"
  )
ggsave("analysis/plots/mpc.pdf", width = 6, height = 2.5, units = "in")
