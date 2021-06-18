library(tidyverse)
trials <- read_csv("./analysis/data/mpc.csv")
ave_d <- trials %>% group_by(proof, infra, constraints, parties) %>% summarize(time=mean(time))
two_pc <- ave_d %>% filter(parties == 3 | infra != "gsz")
mpc <- ave_d %>% filter(parties == 3)
print(two_pc)
print(mpc)
ggplot(data=two_pc, mapping = aes(y = time, x = constraints, color = infra, linetype=infra, shape=infra)) +
  geom_line() +
  geom_point(size=3) +
  scale_y_continuous(trans = "log2") +
  scale_x_continuous(trans = "log2") +
  facet_grid(vars(proof), vars(parties), labeller = label_both) +
  labs(title = "Prover Performance",
       x="Constraints",
       y="Wall-Clock Time (s)"
       )
ggsave("./analysis/plots/mpc.png", width=8, height=8)
