function MergeManager (hash_function, merge_policy) {
    this.merge_policy = merge_policy;
    this.hash_function = hash_function;
    this.data = {};

    this.add = function(newdata) {
        newdata.map(function(val) {
            var hash = this.hash_function(val);
            if (hash in this.data) {
                if (this.merge_policy == MergeManager.MERGE_POLICY_REPLACE) {
                    this.data[hash] = val;
                }
            } else {
                this.data[hash] = val;
            }
        }.bind(this));

        return Object.keys(this.data).map(function(hash) {
            return this.data[hash];
        }.bind(this));
    };
};

MergeManager.MERGE_POLICY_DROP = 0;
MergeManager.MERGE_POLICY_REPLACE = 1;
